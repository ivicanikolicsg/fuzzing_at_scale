
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>

#include "fork_servers.h"
#include "params.h"
#include "scheduler.h"
#include "add_structs.h"

std::vector<std::string> readVector(int parent_pipe[2]) {

    std::vector<std::string> v;

    // Read size of vector from parent
    uint size;
    properAssert(  sizeof(size) == read(parent_pipe[0], &size, sizeof(size)), "read from parent vector size");

    // Read vector from parent
    v.resize(size);
    uint str_size;
    char buffer[kMaxPipeBufferSize];
    for (uint i = 0; i < size; i++) {
        // Read size of string
        properAssert( read(parent_pipe[0], &str_size, sizeof(str_size)) != -1,  "read vector size ");
        properAssert( str_size < kMaxPipeBufferSize, "readVector size too large " + std::to_string(i)+" " +std::to_string( size) );    
        // Read string
        properAssert(  read(parent_pipe[0], buffer, str_size) != -1, "read string");
        buffer[str_size] = '\0';
        v[i] = buffer;
    }

    return v;
}


std::string readString( int parent_pipe[2] ) {
    std::string s;
    char buffer[kMaxPipeBufferSize];
    uint str_size;
    // Read size of string
    properAssert( sizeof(str_size) == read(parent_pipe[0], &str_size, sizeof(str_size)),  "read vector size ");
    properAssert( str_size < kMaxPipeBufferSize, "readString size too large " + std::to_string( str_size) );
    // Read string
    properAssert(  read(parent_pipe[0], buffer, str_size) != -1, "read string");
    buffer[str_size] = '\0';
    return buffer;
}



void writeString( int parent_pipe[2], std::string s) {
    // string size
    uint str_size = s.size();
    str_size = std::min(str_size, kMaxPipeBufferSize-1);
    properAssert( sizeof(str_size) == write(parent_pipe[1], &str_size, sizeof(str_size)) , "write vector str element");
    // string
    properAssert( str_size == write(parent_pipe[1], s.c_str(), str_size),  "write vector str elem");
}


void writeVectorStrings( int parent_pipe[2], const std::vector<std::string> &v ) {

    uint size = v.size();
    // send size
    properAssert( sizeof(size) == write(parent_pipe[1], &size, sizeof(size)), "write vector string lengths");
    // send elements
    for (auto& i : v) {
        // string size
        uint str_size = i.size();
        str_size = std::min( str_size, kMaxPipeBufferSize-1 );
        properAssert( sizeof(str_size) == write(parent_pipe[1], &str_size, sizeof(str_size)) , "write vector str element");
        // string
        properAssert( str_size == write(parent_pipe[1], i.c_str(), str_size),  "write vector str elem");
    }       

}

void startForkserver(int parent_pipe[2], int show_pipe[2] ) {

    // create pipes
    properAssert( pipe(parent_pipe) != -1 , "Cannot init parent pipe for show forkserver" );
    properAssert( pipe(show_pipe) != -1 ,  "Cannot init child pipe for show forkserver" );

    // flush all output before forking
    std::cout<<std::flush;

    pid_t pid = properFork();
    properAssert( pid != -1 , "fork in init show forkserver");
    
    // Child process
    if (pid == 0) {

        // Close unnecessary pipe ends
        close(parent_pipe[1]);
        close(show_pipe[0]);

        while (1) {
            
            // Read from parent
            auto command = readPOD<char>(parent_pipe );
            if( !( kSendShow == command || kSendSym == command || kSendAFL == command  || kSendAFLPP == command || kSendHonggfuzz == command  ) ){ 
                std::cout<< KERR <<"Invalid initial message:" << std::to_string(command) << KNRM << "\n";
                writePOD<char>(show_pipe, kSendError );
                continue;
            }
            else{
                writePOD<char>(show_pipe, kSendOk );
            }
                    
            std::string file_binary_afl, file_binary_only, file_binary_sym;
            std::string param_binary, ld_lib, cwd_lib;
            int has_afl{0}, slave_id{-1};

            auto shmid              = readPOD<int>(parent_pipe );
            auto misc_vector        = readVector( parent_pipe );
            auto folder_target_prog = readString( parent_pipe );
            if( kSendShow == command || kSendSym == command ){
                file_binary_afl    = readString( parent_pipe );
                file_binary_only   = readString( parent_pipe );
                if( kSendSym == command)
                    file_binary_sym     = readString( parent_pipe );
                param_binary       = readString( parent_pipe );
                ld_lib             = readString( parent_pipe );
                cwd_lib            = readString( parent_pipe );
                has_afl            = readPOD<int>(parent_pipe );
            }
            else if( kSendAFL == command ||  kSendAFLPP == command ||  kSendHonggfuzz == command ){
                slave_id           = readPOD<int>(parent_pipe );
                ld_lib             = readString( parent_pipe );
                cwd_lib            = readString( parent_pipe );
            }

            auto proper_end = readPOD<char>(parent_pipe );
            properAssert( kSendEnd == proper_end, "invalid last message" + std::to_string(proper_end) );
            

            // create another thread just for evaluating showmaps

            // fork
            pid_t new_pid = properFork();
            if( new_pid < 0 ){
                writePOD<int>(show_pipe, new_pid );
                continue;
            }
    
            // child thread
            if( 0 == new_pid ){
                
                // try to attach shared mem
                // if cannot, then no need to process further
                Shared_memory *shm  = (Shared_memory *)shmat( shmid, NULL, 0 );
                if( static_cast<void *>(shm) == (void *)-1 ){
                    std::cout<< KINFO <<"Cannot shmat to " << shmid << "\n" << KNRM;
                    writePOD<decltype(getpid())>(show_pipe, -1 );
                    close(parent_pipe[0]);
                    close(show_pipe[1]);
                    exit(-1);
                }

                // otherwise, start processing
                setsid();
                setpgid(0,0);
                writePOD<decltype(getpid())>(show_pipe, getpid() );

                close(parent_pipe[0]);
                close(show_pipe[1]);

                if( kSendAFL == command )
                    runAFL( misc_vector, 
                                    shm,
                                    folder_target_prog, 
                                    slave_id ,
                                    ld_lib,
                                    cwd_lib );

                if( kSendAFLPP == command )
                    runAFLPlusPlus( misc_vector, 
                                    shm,
                                    folder_target_prog, 
                                    slave_id ,
                                    ld_lib,
                                    cwd_lib );

                if( kSendHonggfuzz == command )
                    runHonggfuzz( misc_vector, 
                                    shm,
                                    folder_target_prog, 
                                    slave_id ,
                                    ld_lib,
                                    cwd_lib );


                if( kSendShow == command )
                    checkShowmap(   misc_vector, 
                                    shm, 
                                    folder_target_prog,
                                    file_binary_afl,
                                    file_binary_only,
                                    param_binary,
                                    ld_lib,
                                    cwd_lib,
                                    has_afl );
                else if ( kSendSym == command )
                    checkSym(   misc_vector, 
                                    shm, 
                                    folder_target_prog,
                                    file_binary_afl,
                                    file_binary_only,
                                    file_binary_sym,
                                    param_binary,
                                    ld_lib,
                                    cwd_lib,
                                    has_afl );


                // the child will exit when returning from function
                terminateProgram("Reached unreachable after " + std::to_string(command) );
                //properAssert( 0, "This should never execute" );
                exit(0);

            }
        }

        // Close pipes and exit
        close(parent_pipe[0]);
        close(show_pipe[1]);
        std::cout<<"Exiting showmap forkserver\n";
        exit(0);
    } 
    // Parent process
    else { 
        // Close unnecessary pipe ends
        close(parent_pipe[0]);
        close(show_pipe[1]);
    }

}