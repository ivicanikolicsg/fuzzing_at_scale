#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include <functional>
#include <cmath>
#include <map>
#include <deque>
#include <random>
#include <cassert>
#include <unordered_set>
#include <future>
#include <queue>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <pthread.h>
#include <time.h>
#include <proc/readproc.h>
#include <pwd.h>
//#include <cgroup.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/wait.h>

#include "misc.h"
#include "scheduler.h"
#include "mab.h"
#include "class_fuzzing_context.h"
#include "fork_servers.h"
#include "system-stuff.h"


// settings, global for the whole program
Settings set;

    
std::vector<FuzzingContext*> *ptr_fctx{nullptr};


// file descriptor to /dev/null, when need to discard output
static int dev_null_fd      = -1;


constexpr std::array<uint8_t, 256> count_class_binary = {
    0, 1, 2, 4, 8, 8, 8, 8,
    16, 16, 16, 16, 16, 16, 16, 16,
    32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32,
    64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128
};


// setup all stuff 
void setupMajor(char argv0[], std::string &prog_name, int pipe_main[2], int pipe_side[2] ) {

    setAffinity();

    // pid of main process (so we know if current process is main or child)
    setMainThread(); 
    
    // program name so in fixProcess we known to ignore it
    prog_name   = fs::path( argv0 ).filename() ;

    // file descriptor for /dev/null, so if want to ignore, just duplicate this fd
    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd == -1) {
        std::cout << "[ERROR] could not open /dev/null " << errno << "\n";
        exit(-1);
    }

    // testing mode
    if( set.mode == Run::testing ){
        // to reduce variance introduced by possibly larger number of testcase
        // set num of TC to 1
        set.max_testacases  = 1; 
    }
    else if( set.mode == Run::explore ){
        set.max_testacases  = 10; 
    }
    else if( set.mode == Run::fuzz_compare ){
        set.max_testacases  = 1; 
    }
    else if( set.mode == Run::search ){
        set.max_testacases  = 100000; 
    }

    if( set.mode == Run::testing ){
        set.use_symcc           = false;
    }
    else if( set.mode == Run::explore ){
        set.use_MAB_schedule    = false; 
        set.use_dynamic         = false;
        set.use_var_epsilon     = false;
        set.use_symcc           = false;
    }
    else if( set.mode == Run::fuzz_compare ){
        set.use_MAB_schedule    = true; 
        set.use_dynamic         = true;
        set.use_var_epsilon     = true;
        

        set.use_symcc           = false;
    }
    else if( set.mode == Run::search ){
        set.use_MAB_schedule    = true; 
        set.use_dynamic         = true;
        set.use_var_epsilon     = true;
        set.use_symcc           = false; 
    }

    // start fork servers
    startForkserver( pipe_main, pipe_side );


}



void collectFuzzCandidates( const std::string &folder_fuzz_targets, std::vector<std::string> &candidates ){

    // a few programs  just cannot run, 
    // so explicitly ignore them
    std::set<std::string> bad_progs {
        "signond", 
        "test-email", "test-open", "test-users", "test-proxy",
        "build-script-build", "hlibrary.setup", "shared-test-gc"
        "telepathy-init", "_folks-small-set", "xdg-autostart",
        "try_from-7a3886dccd16a5fb","mldemos","cyclicdeadline",
        "ptsematest","SIZE_LONG.bin",
        "vsftpd", 
        "test_virgl_resource", 
        "yacc", "btyacc", "pbyacc", "byaccj", "rdist", "rdistd"        // create too many files
        ,"lemon"
    };


    candidates.clear();

    for( const auto &entry : fs::directory_iterator(folder_fuzz_targets) ){

        // make sure it is folder
        if( ! entry.is_directory() ) continue;

        // make sure fuzz entry is present
        std::string folder_target_prog { entry.path().string() };
        std::string filepath_fuzz_info {folder_target_prog + "/" + "fuzz_info.txt"} ;
        if( ! folderFileExists(filepath_fuzz_info ) ) continue;

        std::string binary = FuzzingContext::getBinaryFromFolder(folder_target_prog);
        if( bad_progs.contains(binary) ){
            std::cout<<KINFO<<"Ignoring : " << binary << "\n" << KNRM;
            continue;
        }

        candidates.push_back( folder_target_prog );
    }
}


void execveWithOutput( const char *bin, char **args, char**env, bool mute_outputs){
    if( set.output_execve ){
        std::cout<<"execv:\n";
        if( nullptr != env ){
            for( int jj=0; env[jj] != nullptr; jj++)
                std::cout<<env[jj]<<" ";
            std::cout<<"\\\n";
        }
        if( nullptr != bin )
            std::cout<< bin <<" ";
        if( nullptr != args )
            for( int jj=1; args[jj] != nullptr; jj++)
                std::cout<<args[jj]<<" ";
        std::cout<<std::endl;
    }

    std::cout<<"separate:\n";
    for( auto i=1; args[i]; i++)
        std::cout<<i<<":"<<args[i]<<":\n";
    std::cout<<std::endl;;

    //if(0)
    if( mute_outputs ){
        dup2(dev_null_fd, STDOUT_FILENO);
        dup2(dev_null_fd, STDERR_FILENO);
    }

    execve( bin, args, env );

}

// 

void runAFL(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib ){

    const std::vector<std::string> vec_afl_envp{
        "AFL_USE_ASAN=1",
        "AFL_FAST_CAL=1",
        "AFL_NO_AFFINITY=1",
        //"AFL_SKIP_BIN_CHECK=1",
        "AFL_NO_ARITH=1",
        //"AFL_AUTORESUME=1",
        "AFL_PATH="+set.folder_fuzzer,
        "PATH="+set.folder_fuzzer,
        kProcEnvProcess+ std::to_string(shm->id)
    };

    // if slave then change the switch from -M to -S
    if( slave_id >=0 ){
        uint pos = 0;
        for( uint i=0; i< aflpar.size(); i++)
            if( aflpar[i] == "-M" ){
                pos = i;
                break;
            }
        properAssert( pos > 0, "cannot find -M in afl parameters" );
        aflpar[pos]     = "-S";
        aflpar[pos+1]   = "afls"+std::to_string(slave_id);
        // remove -F
        pos = -1;
        for( uint i=0; i< aflpar.size(); i++)
            if( aflpar[i] == "-F" ){
                pos = i;
                break;
            }
        if( pos >=0 ){
            aflpar.erase( aflpar.begin() + pos ); // remove -F
            aflpar.erase( aflpar.begin() + pos ); // remove folder
        }
    }

    char **char_args = getExecvArgs( aflpar );
        
    std::string debug_afl_file = FuzzingContext::produce_debug_afl_file(folder_target_prog);
    bool do_not_show_input = true;
    //do_not_show_input = false;
    if(do_not_show_input) {
        int use_fd = dev_null_fd;
        if( set.save_output_of_fuzzers ){
            // make sure debug file is not too large
            uint trunc_flag = fileSize(debug_afl_file.c_str())  > kMaxDebugSize ? O_TRUNC : 0;  
            int fd_ = open( debug_afl_file.c_str(), O_RDWR | O_CREAT | O_APPEND | trunc_flag, 0644);
            if ( fd_ < 0 ) 
                std::cout<< "Cannot open AFL debug file " << debug_afl_file << "\n";
            else
                use_fd = fd_;
        }
        dup2(use_fd, STDOUT_FILENO);
        dup2(use_fd, STDERR_FILENO);
    }

    char **afl_envp;
    if( ld_lib.size() == 0 )
        afl_envp = getExecvArgs( vec_afl_envp );
    else{ 
        auto new_vec_afl_evnp = vec_afl_envp;
        new_vec_afl_evnp.push_back( "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH" );
        afl_envp = getExecvArgs( new_vec_afl_evnp );
    }

    if( cwd_lib.size() > 0 )
        [[maybe_unused]] int _res = chdir(cwd_lib.c_str());
    
    execveWithOutput( set.filepath_fuzzer.c_str(), char_args, afl_envp, false );
    properAssert( 0, "execv failed");

}

void runAFLPlusPlus(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib ){

    const std::vector<std::string> vec_afl_envp{
        "AFL_USE_ASAN=1",
        "AFL_FAST_CAL=1",
        "AFL_NO_AFFINITY=1",
        //"AFL_SKIP_BIN_CHECK=1",
        "AFL_EXPAND_HAVOC_NOW=1",
        "AFL_AUTORESUME=1",
        "AFL_PATH="+set.folder_fuzzer,
        "PATH="+set.folder_fuzzer,
        kProcEnvProcess+ std::to_string(shm->id)
    };

    // if slave then change the switch from -M to -S
    if( slave_id >=0 ){
        uint pos = 0;
        for( uint i=0; i< aflpar.size(); i++)
            if( aflpar[i] == "-M" ){
                pos = i;
                break;
            }
        properAssert( pos > 0, "cannot find -M in afl parameters" );
        aflpar[pos]     = "-S";
        aflpar[pos+1]   = "afls"+std::to_string(slave_id);
        // remove -F
        pos = -1;
        for( uint i=0; i< aflpar.size(); i++)
            if( aflpar[i] == "-F" ){
                pos = i;
                break;
            }
        if( pos >=0 ){
            aflpar.erase( aflpar.begin() + pos ); // remove -F
            aflpar.erase( aflpar.begin() + pos ); // remove folder
        }
    }

    char **char_args = getExecvArgs( aflpar );
        
    std::string debug_afl_file = FuzzingContext::produce_debug_afl_file(folder_target_prog);
    bool do_not_show_input = true;
    //do_not_show_input = false;
    if(do_not_show_input) {
        int use_fd = dev_null_fd;
        if( set.save_output_of_fuzzers ){
            // make sure debug file is not too large
            uint trunc_flag = fileSize(debug_afl_file.c_str())  > kMaxDebugSize ? O_TRUNC : 0;  
            int fd_ = open( debug_afl_file.c_str(), O_RDWR | O_CREAT | O_APPEND | trunc_flag, 0644);
            if ( fd_ < 0 ) 
                std::cout<< "Cannot open AFL debug file " << debug_afl_file << "\n";
            else
                use_fd = fd_;
        }
        dup2(use_fd, STDOUT_FILENO);
        dup2(use_fd, STDERR_FILENO);
    }

    char **afl_envp;
    if( ld_lib.size() == 0 )
        afl_envp = getExecvArgs( vec_afl_envp );
    else{ 
        auto new_vec_afl_evnp = vec_afl_envp;
        new_vec_afl_evnp.push_back( "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH" );
        afl_envp = getExecvArgs( new_vec_afl_evnp );
    }

    if( cwd_lib.size() > 0 )
        [[maybe_unused]] int _res = chdir(cwd_lib.c_str());
    
    execveWithOutput( set.filepath_fuzzer.c_str(), char_args, afl_envp, false );
    properAssert( 0, "execv failed");

}

void runHonggfuzz(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib ){

    const std::vector<std::string> vec_afl_envp{
        "PATH="+FuzzingContext::produce_folder_misc(folder_target_prog),
        kProcEnvProcess+ std::to_string(shm->id)
    };


    char **char_args = getExecvArgs( aflpar );
        
    std::string debug_afl_file = FuzzingContext::produce_debug_afl_file(folder_target_prog);
    bool do_not_show_input = true;
    //do_not_show_input = false;
    if(do_not_show_input) {
        int use_fd = dev_null_fd;
        if( set.save_output_of_fuzzers ){
            // make sure debug file is not too large
            uint trunc_flag = fileSize(debug_afl_file.c_str())  > kMaxDebugSize ? O_TRUNC : 0;  
            int fd_ = open( debug_afl_file.c_str(), O_RDWR | O_CREAT | O_APPEND | trunc_flag, 0644);
            if ( fd_ < 0 ) 
                std::cout<< "Cannot open AFL debug file " << debug_afl_file << "\n";
            else
                use_fd = fd_;
        }
        dup2(use_fd, STDOUT_FILENO);
        dup2(use_fd, STDERR_FILENO);
    }

    char **afl_envp;
    if( ld_lib.size() == 0 )
        afl_envp = getExecvArgs( vec_afl_envp );
    else{ 
        auto new_vec_afl_evnp = vec_afl_envp;
        new_vec_afl_evnp.push_back( "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH" );
        afl_envp = getExecvArgs( new_vec_afl_evnp );
    }

    if( cwd_lib.size() > 0 )
        [[maybe_unused]] int _res = chdir(cwd_lib.c_str());
    
    execveWithOutput( set.filepath_fuzzer.c_str(), char_args, afl_envp, false );

    properAssert( 0, "execv failed");

}



pid_t startAFL( const FuzzingContext* t,  const bool master, const uint slave_id, int pipe_main[2], int pipe_side[2] ){

    pid_t pid = -1;
                
    // send to pipe all the data
    writePOD<char>(pipe_main, kSendAFL );
    if( readPOD<char>(pipe_side) == kSendOk ){
        writePOD<int>(pipe_main, t->get_shm_id() );
        writeVectorStrings(pipe_main, t->getArgs());
        writeString(pipe_main, t->get_folder_target_prog());
        writePOD<int>(pipe_main, master ? -1 : slave_id );
        writeString(pipe_main, t->get_ld_lib());
        writeString(pipe_main, t->get_cwd_lib());
        writePOD<char>(pipe_main, kSendEnd );

        // get pid
        pid = readPOD<int>(pipe_side);
    }
    return pid;
}


pid_t startAFLPlusPlus( const FuzzingContext* t,  const bool master, const uint slave_id, int pipe_main[2], int pipe_side[2] ){

    pid_t pid = -1;
                
    // send to pipe all the data
    writePOD<char>(pipe_main, kSendAFLPP );
    if( readPOD<char>(pipe_side) == kSendOk ){
        writePOD<int>(pipe_main, t->get_shm_id() );
        writeVectorStrings(pipe_main, t->getArgs());
        writeString(pipe_main, t->get_folder_target_prog());
        writePOD<int>(pipe_main, master ? -1 : slave_id );
        writeString(pipe_main, t->get_ld_lib());
        writeString(pipe_main, t->get_cwd_lib());
        writePOD<char>(pipe_main, kSendEnd );

        // get pid
        pid = readPOD<int>(pipe_side);
    }
    return pid;
}

pid_t startHonggfuzz( const FuzzingContext* t,  const bool master, const uint slave_id, int pipe_main[2], int pipe_side[2] ){

    pid_t pid = -1;

    // send to pipe all the data
    writePOD<char>(pipe_main, kSendHonggfuzz );
    if( readPOD<char>(pipe_side) == kSendOk ){
        writePOD<int>(pipe_main, t->get_shm_id() );
        writeVectorStrings(pipe_main, t->getArgs());
        writeString(pipe_main, t->get_folder_target_prog());
        writePOD<int>(pipe_main, master ? -1 : slave_id );
        writeString(pipe_main, t->get_ld_lib());
        writeString(pipe_main, t->get_cwd_lib());
        writePOD<char>(pipe_main, kSendEnd );

        // get pid
        pid = readPOD<int>(pipe_side);
    }
    return pid;
}


void startOne(  FuzzingContext* ptr_ctx,                             
                int pipe_main[2], 
                int pipe_side[2] ) {

    pid_t pid{0};
    if( Fuzzer::AFL == set.fuzzer ) 
        pid = startAFL( ptr_ctx, true , 0, pipe_main, pipe_side );
    else if( Fuzzer::AFLPP == set.fuzzer ) 
        pid = startAFLPlusPlus( ptr_ctx, true , 0, pipe_main, pipe_side );
    else if( Fuzzer::Honggfuzz == set.fuzzer ) 
        pid = startHonggfuzz( ptr_ctx, true , 0, pipe_main, pipe_side );
    else
        properAssert( 0, "inappropriate fuzzer");
        
    ptr_ctx->setPid( pid );
    ptr_ctx->fuzzInit();
    ptr_ctx->increaseNoBootstrap();

}


void createFuzzingContextes( const std::vector<std::string> &fuzz_candidates, std::vector<FuzzingContext*> &fctx ) {

    fctx.clear();

    uint tot_launched = 0;
    for( auto &folder_target_prog: fuzz_candidates ){

        FuzzingContext *ptr_ctx = new FuzzingContext(folder_target_prog, set.mode_ow_cont );
        if( ptr_ctx->getState() == State::killed )
            continue;

        fctx.push_back( ptr_ctx );
        if( ++tot_launched >= set.max_launched )
            break;

        std::cout<< tot_launched << "/" << set.max_launched
                 <<"  has: " << ptr_ctx->get_has_afl() << ptr_ctx->get_has_sym()
                 << " " << ptr_ctx->getFolderRoot() << "\n";
    }
}

void checkShowmap( 
        std::vector<std::string> &showmap_cands,
        Shared_memory *shm,
        std::string folder_target_prog,
        std::string file_binary_afl,
        std::string file_binary_only,
        std::string oparam_binary,
        std::string ld_lib,
        std::string cwd_lib,
        int has_afl
    ){

    shm->to_process_show    = showmap_cands.size() ;
    shm->cur_process_show   = 0;
    shm->showmap_session++;

    std::string debug_showmap_file = FuzzingContext::produce_debug_showmap_file(folder_target_prog);
    int use_fd = dev_null_fd;
    if( set.save_output_of_fuzzers ){ 
        // make sure debug file is not too large
        uint trunc_flag = fileSize(debug_showmap_file.c_str())  > kMaxDebugSize ? O_TRUNC : 0;  
        int fd_ = open( debug_showmap_file.c_str(), O_RDWR | O_CREAT | O_APPEND | trunc_flag, 0644);
        if ( fd_ < 0 ) 
            std::cout<< "Cannot open showmap debug file " << debug_showmap_file << "\n";
        else
            use_fd = fd_;
    }
    dup2(use_fd, STDOUT_FILENO);
    dup2(use_fd, STDERR_FILENO);


    uint processed{0};
    for( uint i=0; i< showmap_cands.size(); i++){

        std::cout<<"\n----------  Process showmap " << (i+1)<<" / " << showmap_cands.size() << "  -------" << std::endl;;

        auto fpath = showmap_cands[i];
        shm->cur_process_show = i;

        auto filepath_testcase      = fpath;
        auto filepath_temp_testcase = FuzzingContext::produce_folder_showmap_test(folder_target_prog) + "/" + std::string(fs::path( fpath ).filename());
        auto filepath_showmap       = FuzzingContext::produce_folder_misc(folder_target_prog) + "/showmap-"+std::string(fs::path( fpath ).filename())+".txt";
        auto folder_local_afl_show  = FuzzingContext::produce_folder_misc(folder_target_prog) + "/";

        std::vector<std::string> showmap_args;
        showmap_args.push_back("afl-showmap");
        showmap_args.push_back("-r");
        showmap_args.push_back("-t");
        showmap_args.push_back(std::to_string(int(set.max_time_showmap * 1000)));
        showmap_args.push_back("-m");
        showmap_args.push_back(set.afl_mem_limit);
        showmap_args.push_back("-o");
        showmap_args.push_back(filepath_showmap);
        if( ! has_afl )
            showmap_args.push_back(kBinModeSwitch);        // binary only mode    
        showmap_args.push_back("--");
        showmap_args.push_back(  has_afl ? file_binary_afl : file_binary_only );
        std::string param_binary = oparam_binary;
        size_t pos = param_binary.find(" @@");
        if( pos != std::string::npos ){
            param_binary.replace(pos, std::string(" @@").length(), "");
            if( param_binary.size() > 0 )  
                showmap_args.push_back( param_binary );
            showmap_args.push_back( filepath_temp_testcase ); 
        }

        if( fs::exists(filepath_showmap) ) 
            fs::remove_all( fs::path{filepath_showmap} );
        fs::copy( filepath_testcase, filepath_temp_testcase, fs::copy_options::overwrite_existing );

        auto smart_showmap_args = std::make_unique<char*[]>(showmap_args.size() + 1  );
        for( uint i=0; i< showmap_args.size(); i++)
            smart_showmap_args.get()[i] = const_cast<char*>(showmap_args[i].c_str()); 
        smart_showmap_args.get()[ showmap_args.size() ] = NULL;
            

        pid_t pid = properFork();
        if( pid < 0 ){
            std::cout<< KINFO << "Fork failure" << KNRM << "\n";
            continue;
        }
        if( 0 == pid ){

            //setsid();
            //setpgid(0,0); 

            if( cwd_lib.size() > 0 )
                [[maybe_unused]] int _ret = chdir(cwd_lib.c_str());

            auto envp = getExecvArgs(std::vector<std::string>{
                "AFL_MAP_SIZE=80000", "PATH="+folder_local_afl_show, //"PATH="+kFolderAFLPPShowmap,
                "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH",
                kProcEnvProcess+ std::to_string(shm->id)
                });
            execveWithOutput( (folder_local_afl_show+"afl-showmap").c_str()/*set.filepath_fuzzer_showm.c_str()*/, smart_showmap_args.get(), envp, set.mute_programs_output );
            properAssert( 0, "execv failed" );
        }

        [[maybe_unused]]  int status = timeChild( pid, set.max_time_showmap ); 


        // pull the showmap
        uint tc_score = 0;  // sum of 0/1 predicates for new afl coverage (either new edge or new edge multiplicity)
        uint edges    = 0;  // sum of 0/1 predicates for new edge

        // read map
        if( ! fs::exists(filepath_showmap) ){
            std::cout<<"showmap result file does not exist:" << filepath_showmap <<"\n";
            continue;
        }
        std::ifstream mf(filepath_showmap );
        std::string l;
        while( mf >> l ){
            if( l.size() < 8 || l[6] != ':' ){
                std::cout << KERR <<"Weird showmap line:"<<l<<":\n";
                continue;
            }
            uint index  = stoi( l.substr(0,6) );
            uint m      = stoi( l.substr(7) );

            index = index % (1<<16) ; // in case AFL uses map larger than 64KB
            if( m >= 256 ){
                std::cout << KERR <<"Bad index/map in line:"<<l<<"\n";
                continue;
            }
            // modify m because AFL++ uses different then AFL
            // i.e. instead of AFL 1,2,4,8,16,..., AFL++ uses 1,2,3,4,5...
            //if( m >= 7 ) m = 7;
            //m = 0 == m ? 0 : 1<<m;
            m = count_class_binary[m];

            tc_score += (shm->show[index] | (char)m ) != shm->show[index];
            edges += m && 0 == shm->show[index];
            shm->show[index] |= (char)m;
        }

        std::cout<<"newfound coverage : "<<processed << " : " << tc_score<< " " << edges <<"\n";

        // if in exploration mode and found additional coverage after the first TC
        // it means the program is good 
        // and no need to fuzz this program further
        if( set.mode == Run::explore && tc_score > 0 
            && (shm->showmap_session > 1 || processed > 0 )   
        ){
            std::cout<<"Positive explore candidate"<<std::endl;
            shm->state  = State::killed;
            shm->action = Action::out; 
            std::ofstream outfile(folder_target_prog + "/good_candidate.txt");
            outfile.close();
            FuzzingContext::fuzzKillStatic(shm);
            exit(0);
        }

        // if these are the initial TC, then do not take them into account 
        if( 1 == shm->showmap_session && set.max_testacases > 0 && processed++ < set.max_testacases ){
            tc_score = 0;
            edges = 0;
        }

        if( tc_score > 0 || edges > 0)
            FuzzingContext::set_add_scoreStatic( shm, tc_score, edges );
    }

    shm->cur_process_show    = shm->to_process_show;
    FuzzingContext::switchToFuzzingStatic( shm );
    shm->showmap_pid = -1;

    exit(0);

}



void checkSym( 
        std::vector<std::string> &sym_cands, 
        Shared_memory *shm,
        std::string folder_target_prog,
        std::string file_binary_afl,
        std::string file_binary_only,
        std::string file_binary_symcc,
        std::string oparam_binary,
        std::string ld_lib,
        std::string cwd_lib,
        int has_afl
    ){

    shm->to_process_sym     = sym_cands.size() ;
    shm->cur_process_sym    = 0;

    std::string debug_sym_file = FuzzingContext::produce_debug_sym_file(folder_target_prog);
    int use_fd = dev_null_fd;
    if( set.save_output_of_fuzzers ){
        // make sure debug file is not too large
        uint trunc_flag = fileSize(debug_sym_file.c_str())  > kMaxDebugSize ? O_TRUNC : 0;  
        int fd_ = open( debug_sym_file.c_str(), O_RDWR | O_CREAT | O_APPEND | trunc_flag, 0644);
        if ( fd_ < 0 ) 
            std::cout<< "Cannot open sym debug file " << debug_sym_file << "\n";
        else
            use_fd = fd_;
    }
    dup2(use_fd, STDOUT_FILENO);
    dup2(use_fd, STDERR_FILENO);


    // cleared on every call to this function, 
    // better if in shared memory, but std set cannot be in shared
    std::set<std::size_t> symcc_hash_values;

    // temp show; updated locally
    char tshow[1<<16];
    memcpy( tshow, shm->show, 1<<16 );

    for( uint i=0; i< sym_cands.size(); i++){

        auto fpath = sym_cands[i];
        shm->cur_process_sym = i;

        std::cout<<"\nCandidate " << (i+1)<<" / " << sym_cands.size() << fpath << "\n";

        // erase temp folder
        std::string output_fold = FuzzingContext::produce_folder_symcc(folder_target_prog) +"/temp";
        if( folderFileExists(output_fold))
            fs::remove_all( fs::path{output_fold} );
        fs::create_directory( fs::path{output_fold} );

        // execute with symcc
        fs::copy( fs::path{fpath}, fs::path{FuzzingContext::produce_file_symcc_input(folder_target_prog)}, fs::copy_options::overwrite_existing );
        setCurrentAction(Action::symcc);
        pid_t pid = properFork();
        if( pid < 0 ){
            std::cout<< KINFO << "Fork failure" << KNRM << "\n";
            continue;
        }
        if( 0 == pid ) {

            if( cwd_lib.size() > 0 )
                [[maybe_unused]] int _ret = chdir(cwd_lib.c_str());
    
            char **envp = getExecvArgs(std::vector<std::string>{
                "SYMCC_OUTPUT_DIR="+output_fold,
                "SYMCC_INPUT_FILE="+FuzzingContext::produce_file_symcc_input(folder_target_prog),
                "SYMCC_AFL_COVERAGE_MAP="+ FuzzingContext::produce_folder_symcc(folder_target_prog) + "/aflshowmap",
                "SYMCC_ENABLE_LINEARIZATION=1",
                "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH",
                kProcEnvProcess+ std::to_string(shm->id)
            });

            auto param_binary = oparam_binary;
            std::vector<std::string> ar{fs::path( file_binary_symcc ).filename()};
            size_t pos = param_binary.find(" @@");
            if( pos != std::string::npos ){
                param_binary.replace(pos, std::string(" @@").length(), "");
                if( param_binary.size() > 0 )
                    ar.push_back( param_binary );
                ar.push_back( FuzzingContext::produce_file_symcc_input(folder_target_prog));
            }
            char **char_args = getExecvArgs(ar);
            execveWithOutput(file_binary_symcc.c_str(), char_args, envp, true );
            properAssert( 0, "execv failed" );
        }

        [[maybe_unused]]  int status = timeChild( pid, set.max_time_symcc ); 

        auto symcc_fold = output_fold;

        // check for new files
        for( const auto &tc : fs::directory_iterator(symcc_fold) ){

            // if same file as before, then defitely not new
            auto h = fs::hash_value( tc );
            if( symcc_hash_values.contains(h) ){ 
                std::cout<<"="<<std::flush;
                continue;
            }
            symcc_hash_values.insert( h );

            auto filepath_testcase      = tc.path();
            auto filepath_temp_testcase = FuzzingContext::produce_folder_showmap_test(folder_target_prog) + "/" + std::string(fs::path( fpath ).filename()) + "-symcc";
            auto filepath_showmap       = FuzzingContext::produce_folder_misc(folder_target_prog) + "/showmap-symcc.txt";

            std::cout<<"process showmap in symcc  " << filepath_testcase << " .... "<<std::endl;

            std::vector<std::string> showmap_args;
            showmap_args.push_back("afl-showmap");
            showmap_args.push_back("-r");
            showmap_args.push_back("-t");
            showmap_args.push_back(std::to_string(int(set.max_time_showmap * 1000)));
            showmap_args.push_back("-m");
            showmap_args.push_back(set.afl_mem_limit);
            showmap_args.push_back("-o");
            showmap_args.push_back(filepath_showmap);
            if( ! has_afl )
                showmap_args.push_back(kBinModeSwitch);        // binary only mode    
            showmap_args.push_back("--");
            showmap_args.push_back(  has_afl ? file_binary_afl : file_binary_only );
            auto param_binary = oparam_binary;
            size_t pos = param_binary.find(" @@");
            if( pos != std::string::npos ){
                param_binary.replace(pos, std::string(" @@").length(), "");
                if( param_binary.size() > 0 )
                    showmap_args.push_back( param_binary );
                showmap_args.push_back( filepath_temp_testcase ); 
            }


            fs::copy( filepath_testcase, filepath_temp_testcase, fs::copy_options::overwrite_existing );

            auto smart_showmap_args = std::make_unique<char*[]>(showmap_args.size() + 1  );
            for( uint i=0; i< showmap_args.size(); i++)
                smart_showmap_args.get()[i] = const_cast<char*>(showmap_args[i].c_str()); 
            smart_showmap_args.get()[ showmap_args.size() ] = NULL;

            setCurrentAction( Action::showmap );
            pid_t pid = properFork();
            if( pid < 0 ){
                std::cout<< KINFO << "Fork failure" << KNRM << "\n";
                continue;
            }
            if( 0 == pid ){

                if( cwd_lib.size() > 0 )
                    [[maybe_unused]] int _ret = chdir(cwd_lib.c_str());
        
                char **envp = getExecvArgs(std::vector<std::string>{
                    "AFL_MAP_SIZE=80000", "PATH="+set.folder_fuzzer,
                    "LD_LIBRARY_PATH="+ld_lib+":$LD_LIBRARY_PATH",
                    kProcEnvProcess+ std::to_string(shm->id)
                });
                execveWithOutput( set.filepath_fuzzer_showm.c_str() , smart_showmap_args.get(), envp, true );
                properAssert( 0, "execv failed" );
            }

            [[maybe_unused]]  int status = timeChild( pid, set.max_time_showmap * 1.25 ); 

            // read map
            int tc_score = 0;
            if( ! fs::exists(filepath_showmap) ) {
                std::cout << KINFO << "[-]" << KNRM;
                continue;
            }
            std::ifstream mf(filepath_showmap );
            std::string l;
            while( mf >> l ){
                if( l.size() < 8 || l[6] != ':' ){
                    std::cout << KERR <<"Weird showmap line:"<<l<<":\n";
                    continue;
                }
                uint index  = stoi( l.substr(0,6) );
                uint m      = stoi( l.substr(7) );
                index = index % (1<<16);
                if( m >= 256 ){
                    std::cout << KERR <<"Bad index/map in line:"<<l<<"\n";
                    continue;
                }
                m = count_class_binary[m];
                tc_score += (tshow[index] | (char)m ) != tshow[index];
                tshow[index] |= (char)m;
            }

            // if new coverage or crash then copy the TC to 'queue' folder
            if( tc_score > 0 || WIFSIGNALED(status) ){
                fs::copy( tc , FuzzingContext::produce_folder_symcc(folder_target_prog) + "/queue/id:" + numToStr( shm->symcc_id,6));
                (shm->symcc_id)++;
            }
        }          
    }

    shm->cur_process_sym    = shm->to_process_sym;
    FuzzingContext::switchToFuzzingStatic( shm );
    shm->sym_pid = -1;

    exit(0);
}


void stepFuzzOrUpdateMap(   std::vector<FuzzingContext*> &running,
                            std::vector<FuzzingContext*> &stopped,
                            int pipe_main[2], 
                            int pipe_side[2]
){

    if( running.size() == 0 ) return;

    // start of cycle
    static std::chrono::time_point<std::chrono::high_resolution_clock> time_prev_start = std::chrono::system_clock::now();
    double time_passed = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now() - time_prev_start ).count()/1000.0 ;
    time_prev_start = std::chrono::system_clock::now();
    static double time_showmap_tot{0}, time_showmap_folds{0};

    for( int i = running.size()-1; i>=0; i-- ){
        const auto t {running[i]};

        std::cout<<std::setw(3)<<i
            <<" " << t->get_has_afl()<<t->get_has_sym()<<t->get_has_cmp()
            <<" " << t->getNoCrashes() 
            <<" " << std::setw(4)<<getActionString(t->getAction())
            <<" " << std::setw(4)<<t->getNumTC()
            <<" " << t->getMab().debug(0,0)
            <<" " << t->getFolderRoot()
            << std::endl;


        // add_score to the score
        t->updateScoreState(time_passed);

        // if it already produce a lot of crashes then just remove from fuzzing
        if( Run::search == set.mode && t->getNoCrashes() > set.stop_if_crashes ){
            std::cout << KINFO <<"Too many crashes already: " << t->getNoCrashes() << KNRM << std::endl;
            t->fuzzKill();
            t->get_shm()->state = State::killed;
            running.erase( running.begin() + i );
        }

        // if afl fuzz and it is not responding then this is dead beat,
        // either try again if previously failed due to timings (can happen because busy schedule) 
        // or remove it from further consideration
        if ( t->getAction() == Action::fuzz && ! isProcessValid( t->getPid() ) ) {
            std::cout << KINFO "Non-responsive afl action. \n" << KNRM;

            // if AFL setup failed due to timeouts, try to bootstrap again (but not more than max_afl_boostrap_trails)
            if(     t->get_no_bootstraps() < set.max_no_bootstrap_trials 
                &&  fileHasSubstring(t->get_debug_afl_file(), "test cases time out or crash") 
            ){
                std::cout<<"Bootstrapping again" << std::endl;
                t->aflReinit();
                stopped.push_back( t  );
            }
            // if Honggfuzz 
            else if( t->get_no_bootstraps() < set.max_no_bootstrap_trials 
                &&  Fuzzer::Honggfuzz == set.fuzzer 
            ){
                std::cout<<"Bootstrapping again " << t->get_no_bootstraps() << std::endl;
                t->honggReinit();
                stopped.push_back( t  );
            }
            else {
                t->get_shm()->state = State::killed;
            }
            running.erase( running.begin() + i );
            continue;
        }


        // if showmap or sym and they are not responding then switch to fuzzing
        if ( t->getAction() == Action::showmap && ! isProcessValid(t->get_shm()->showmap_pid)  ) {
            std::cout << KINFO "Non-responsive nonafl action " << getActionString( t->getAction()) 
                      << ". Switch to fuzzing " << t->get_shm()->showmap_pid 
                      << "   " << t->getPid()<< "\n" << KNRM;
            t->get_shm()->showmap_pid = -1;
            t->switchToFuzzing();
            continue;
        }
        if (  t->getAction() == Action::symcc && ! isProcessValid( t->get_shm()->sym_pid )  ) {
            std::cout << KINFO "Non-responsive nonafl action " << getActionString( t->getAction()) << ". Switch to fuzzing \n" << KNRM;
            t->get_shm()->sym_pid = -1;
            t->switchToFuzzing();
            continue;
        }


        // if symcc is running for too long, then stop it temporarily
        if( t->getAction() == Action::symcc && t->get_symcc_running_time() > set.max_time_consecutive_symcc * 1000 ){
            //
            std::cout<<"Symcc running too much \n";
            kill( t->get_shm()->sym_pid, SIGSTOP ); 
            t->get_shm()->paused_symcc = true;
            t->set_time_of_pause_symcc();
            t->set_time_of_stop_symcc();
        
            //if( kill( t->getPid(), SIGCONT )  == -1 )
            if( killpg( getpgid(t->getPid()), SIGCONT )  == -1 )
                std::cout<<"Cannot start process "<< std::endl;
            else
                std::cout<<"Successfully started main thread "<< std::endl;
            t->get_shm()->action = Action::fuzz;

            continue;
        }

        // if AFL fuzz, then try to switch to showmap to check for new coverage
        if (    t->getAction() == Action::fuzz && t->getTimeFuzzed() >= set.secs_wait_to_start_showmap 
            &&  timeDiffSecs(time_prev_start, t->get_time_last_showmap()) >= set.secs_between_showsymcc
            &&  t->AFLSetupIsDone() ) {

            auto tmp_time          = std::chrono::system_clock::now();

            t->set_time_last_showmap();

            auto showmap_cands = t->getShowmapCandidates();    
            if( showmap_cands.size() > 0 ){
                // stop the fuzzer
                t->stopAFL();
                // launch showmap
                t->setAction(Action::showmap);
                t->setNumTC( showmap_cands.size() );

                pid_t pid = -1;
                // send to pipe all the data
                writePOD<char>(pipe_main, kSendShow );
                if( readPOD<char>(pipe_side) == kSendOk ){
                    writePOD<int>(pipe_main, t->get_shm_id() );
                    writeVectorStrings(pipe_main,showmap_cands);
                    writeString(pipe_main, t->get_folder_target_prog());
                    writeString(pipe_main, t->get_file_binary_afl());
                    writeString(pipe_main, t->get_file_binary_only());
                    writeString(pipe_main, t->get_param_binary());
                    writeString(pipe_main, t->get_ld_lib());
                    writeString(pipe_main, t->get_cwd_lib());
                    writePOD<int>(pipe_main, static_cast<int>(t->get_has_afl()) );
                    writePOD<char>(pipe_main, kSendEnd );

                    // get pid
                    pid = readPOD<int>(pipe_side);
                }
                // if negative, it means something failed, so continue with 
                // normal, AFL fuzzing
                if( pid < 0 ){
                    t->setAction(Action::fuzz);
                    t->switchToFuzzing();
                }
                // capture the pid
                else{
                    t->setPidShowmap( pid );
                }
                
                time_showmap_folds += timeElapsedMSecs( tmp_time) / 1000.0;
            }
            time_showmap_tot += timeElapsedMSecs( tmp_time) / 1000.0;
        }


        // check if can switch to symcc
        if ( set.use_symcc 
            && t->get_has_sym() && t->getAction() == Action::fuzz && t->getTimeFuzzed() >= set.secs_wait_to_start_symcc 
            && timeDiffSecs(time_prev_start, t->get_time_last_symcc()) >= set.secs_between_showsymcc
            && t->AFLSetupIsDone() ) {

            t->set_time_last_symcc();

            // if symcc paused previously then continue
            if(    t->get_shm()->paused_symcc ){
                if( t->get_symcc_pause_time() > set.min_time_pause_symcc * 1000 ){
                    t->get_shm()->paused_symcc = false;
                    t->setAction(Action::symcc);
                    t->set_time_of_start_symcc();
                    kill( t->get_shm()->sym_pid, SIGCONT );
                }
                continue;
            }

            // otherwise, check for new candidates and process them
            auto sym_cands = t->getSymCandidates();
            if( sym_cands.size() > 0 ){
                // stop the fuzzer              
                t->stopAFL();
                // launch symcc
                t->setAction(Action::symcc);
                t->get_shm()->paused_symcc     = false;
                t->set_time_of_start_symcc();
                t->set_time_of_stop_symcc();

                pid_t pid = -1;
                // send to pipe all the data
                writePOD<char>(pipe_main, kSendSym );
                if( readPOD<char>(pipe_side) == kSendOk ){

                    writePOD<int>(pipe_main, t->get_shm_id() );
                    writeVectorStrings(pipe_main,sym_cands);
                    writeString(pipe_main, t->get_folder_target_prog());
                    writeString(pipe_main, t->get_file_binary_afl());
                    writeString(pipe_main, t->get_file_binary_only());
                    writeString(pipe_main, t->get_file_binary_symcc());
                    writeString(pipe_main, t->get_param_binary());
                    writeString(pipe_main, t->get_ld_lib());
                    writeString(pipe_main, t->get_cwd_lib());
                    writePOD<int>(pipe_main, static_cast<int>(t->get_has_afl()) );
                    writePOD<char>(pipe_main, kSendEnd );

                    // get pid
                    pid = readPOD<int>(pipe_side);
                }
                // if negative, it means something failed, so continue with AFL
                if( pid < 0 ){
                    t->setAction(Action::fuzz);
                    t->switchToFuzzing();
                }
                // normal, capture the pid
                else{
                    t->setPidSym( pid );
                }

            }
        }

    }
}


// victim is the program with lowest score
// which is lowest (discounted) achieved coverage per unit of time
int chooseVictim( const std::vector<FuzzingContext*> &running ){
    
    uint worse_index = 0;
    double worse_score = running[0]->getCurScore();
    for( uint i=0; i< running.size(); i++ ){
        if( running[i]->getCurScore() < worse_score ){
            worse_score = running[i]->getCurScore();
            worse_index = i;
        }
    }
    return worse_index;
}


int chooseNextWithMAB( const std::vector<FuzzingContext*> &stopped){

    // choose the index according to the bandits
    std::vector<MAB*> mabs;
    for( const auto &o: stopped )
        mabs.push_back( &o->getMab() );
    int index = mabSample( mabs);
    properAssert( index >= 0,  "in chooseNext index < 0");

    return index;
}


uint evict( int n,
            std::vector<FuzzingContext*> &running,
            std::vector<FuzzingContext*> &stopped
 ){
    int nn = 0;
    while( nn < n  && running.size() > 0  ) {
        // if Round Robin schedule, then evict the first
        // otherwise, evict the one which produced the lowest coverage
        int index = set.use_MAB_schedule ? chooseVictim( running ) : 0 ;
        index = 0;
        if( index >= 0 ){
            stopped.push_back( running[index] );
            // stop the fuzzing 
            running[index]->fuzzStop();
            running[index]->printStats("[-] Stopping ");
            running.erase( running.begin() + index );
        }
        else 
            break;
        nn++;
    }
    return nn;
}

int schedule( int n,
            std::vector<FuzzingContext*> &running,
            std::vector<FuzzingContext*> &stopped,
            int pipe_main[2], 
            int pipe_side[2]
){
    int nn = 0;
    while( nn < n && stopped.size() >  0 ){
        // if Round Robin schedule, then just choose the first
        // otherwise, decide based on MAB 
        uint index = set.use_MAB_schedule ? chooseNextWithMAB( stopped ) : 0 ;
        stopped[index]->printStats("[+] Schedule ");
        if( stopped[index]->getState() == State::init || stopped[index]->fuzzCont() ){
            if( stopped[index]->getState() == State::init )
                startOne( stopped[index], pipe_main, pipe_side  );
            running.push_back( stopped[index] );
        }
        stopped.erase( stopped.begin() + index );
        nn++;
    }
    return nn;
}


// kill process
void terminatePidProg(  const proc_t &p, 
                        std::string &&message, 
                        double &time_kill, 
                        double &time_tot, 
                        uint &times_kill,
                        std::ofstream &out ){
    out << KINFO << "killing: " << message<<" : " << p.ppid <<" " << p.tid <<" " << p.cmd << "\n" << KNRM;
    auto time_tmp       = std::chrono::system_clock::now();
    kill( p.tid, SIGKILL );
    double time_delta   = timeElapsedMSecs( time_tmp ) /1000;
    time_kill           += time_delta;
    time_tot            -= time_delta;
    times_kill++;
}

// we watermark processes spun by our program by adding environment variable kProcEnvProcess when 
// calling execve. So, this function checks if such env var is present
uint checkEnv( const proc_t &p ) {
    static const size_t n = kProcEnvProcess.size();
    if( p.environ == nullptr ) return false;
    for( int i=0; p.environ[i]; i++){
        if( strncmp( p.environ[i], kProcEnvProcess.c_str(), n ) == 0 ){ 
            uint id = atoi( p.environ[i] + n ); 
            return id;
        }
    }
    return 0;
}

// it helps clean unnecessary processes spun during fuzzing:
// 1) when fuzzing uninstrumented binaries, AFL calls qemu, which in turn can use huge memory; so we kill those
// 2) some fuzzed programs change parent, so cannot be stopped, killed, etc. ; so we kill those
auto fixProcesses(  const std::string &prog_name, 
                    std::ofstream &log_fix ){

    // set affinity of this thread (so it uses the same assigned CPUs)
    setAffinity();

    log_fix <<"\nRound: " << std::endl;

    std::set<uint> terminate;
    auto tmp_time_now = std::chrono::system_clock::now();

    std::unordered_map<uint, uint> prog_id_to_tot_counts, prog_id_to_R_counts;

    static std::unordered_map<pid_t,uint> pid_to_id;
    static std::unordered_map<pid_t,double> pid_to_spent_seconds;
    static std::unordered_map<pid_t,std::chrono::time_point<std::chrono::system_clock>> pid_to_time_point;
    
    // if keeps persisting then stop fuzzing this program
    static std::unordered_map< uint, uint > times_term;

    std::unordered_set<pid_t> seen_pids;

    static double time_tot{0}, time_kill{0};
    static uint times_tot{0}, times_kill{0};
    auto time_of_start          = std::chrono::system_clock::now();

    PROCTAB* proc = openproc(PROC_FILLSTAT | PROC_FILLCOM | PROC_FILLENV | PROC_FILLUSR );
    proc_t p;
    memset(&p, 0, sizeof(p));
    std::string user = getpwuid(getuid())->pw_name;
    uint count{0}, termed{0};
    auto ticks = sysconf(_SC_CLK_TCK);
    while ((readproc(proc, &p)) != NULL) {

        count++;

        // user must be current user
        if( strcmp(p.euser, user.c_str()) != 0 ) continue; 

        // ignore main prog
        if( strcmp(p.cmd, prog_name.c_str()) == 0 ) continue; 

        pid_t pid = p.tid;
        seen_pids.insert( pid );

        if( ! pid_to_id.contains(pid) )
            pid_to_id[pid] = checkEnv( p );

        uint prog_id = pid_to_id[pid];
        if( prog_id == 0 ) continue;            // need to have the watermark


        // if high CPU usage, i.e. more than 200%, then kill it
        double spend_seconds = (p.utime + p.stime + 0.0) / ticks ;
        double passed_seconds = 1000000.0;
        double spent_diff = spend_seconds;
        if( pid_to_time_point.contains(pid) )
            passed_seconds  = timeElapsedMSecs( pid_to_time_point[pid] ) / 1000.0;
        if( pid_to_spent_seconds.contains(pid) )
            spent_diff      = spend_seconds - pid_to_spent_seconds[pid];
        pid_to_time_point[pid] = std::chrono::system_clock::now();
        pid_to_spent_seconds[pid] = spend_seconds;

        double cpu_usage = 100.0 * spent_diff / passed_seconds;
        if( cpu_usage > 50 || p.rss > 100000 )
        {
            log_fix << std::fixed 
                    << std::setw(3) << std::setprecision(0) << cpu_usage 
                    //<< "  " << std::setw(5) << std::setprecision(1) << spent_diff 
                    << "  " << std::setw(5) << std::setprecision(1) << passed_seconds 
                    << "  " << std::setw(7) << p.rss  
                    << "  " << std::setw(7) << p.ppid  
                    << "  " << std::setw(5) << prog_id  
                    << "  " << p.cmd << std::endl;
        }
        if( cpu_usage > kMaxCPUUsage ) {
            terminatePidProg( p, "high CPU usage " +std::to_string(cpu_usage), time_kill, time_tot, times_kill, log_fix );
            //if( Fuzzer::AFLPP == set.fuzzer || Run::fuzz_compare != set.mode )
                terminate.insert( prog_id );            
        }

        // counters how many are running and how many in total per program id
        if( p.state == 'R' )
            prog_id_to_R_counts[prog_id]++;
        prog_id_to_tot_counts[prog_id] ++;

        // terminate if high mem usage
        if( p.rss > 1000 * kMaxMemUsageInMB ){
            terminatePidProg( p, "high MEM usage (" +std::to_string(p.rss/1000)+" > " + std::to_string(kMaxMemUsageInMB) + ") ", time_kill, time_tot, times_kill, log_fix );
            termed++;

            times_term[ prog_id ] ++;
            if(     times_term[  prog_id ] > 10  
                    && ( Fuzzer::AFLPP == set.fuzzer ||  Fuzzer::AFL == set.fuzzer || Run::fuzz_compare != set.mode )            
            ){
                log_fix << "Need to terminate: " << prog_id << "\n";
                terminate.insert( prog_id );
            }
        }

        // terminate if parent changed to systemd
        if( p.ppid == 1 ) {
            terminatePidProg( p,  "parent changed to systemd", time_kill, time_tot, times_kill, log_fix );
            termed++;

            times_term[ prog_id ] ++;
            if(     times_term[prog_id] > 10
                //    && ( Fuzzer::AFLPP == set.fuzzer || Run::fuzz_compare != set.mode )
            ){
                log_fix << "Need to terminate: " << prog_id << "\n";
                terminate.insert( prog_id );
            }
        }

    }

    // remove from pid_to_id unseen pids so there will be no problems if same pid is assigned to different process
    std::unordered_set<pid_t> to_remove;
    for( auto &[k,v]: pid_to_id )
        if( ! seen_pids.contains( k ) )
            to_remove.insert( k );
    for( auto k: to_remove ){
        pid_to_id.erase( k );
        pid_to_time_point.erase(k); 
        pid_to_spent_seconds.erase(k);
    }


    time_tot += timeElapsedMSecs( time_of_start ) / 1000.0;
    times_tot++;

    // logs
    log_fix<<"fixProcesses time: " << time_kill <<" " << time_tot 
            <<"   " << times_tot<<" " << times_kill << std::endl;
    log_fix<<"Tot/termed: " << count << " " << termed << std::endl;
    for( auto a:terminate)
        log_fix<<"willterm: " << terminate.size()<<" " << a <<"\n";
    for( auto [k,v]: prog_id_to_tot_counts )
        if( v > 4)
            log_fix<<"Tot counts: " << k <<" : " << v << std::endl;
    for( auto [k,v]: prog_id_to_R_counts )
        if( v > 1)
            log_fix<<"R   counts: " << k <<" : " << v << std::endl;
    log_fix <<"Counts size: " 
        << " " << prog_id_to_tot_counts.size()
        << " " << prog_id_to_R_counts.size() << std::endl;

    return std::make_tuple(terminate, timeElapsedMSecs( tmp_time_now ) );
}





int main(int argc,  char **argv) {

    std::vector<FuzzingContext*> fctx; 
    ptr_fctx = &fctx;

    // parse input params
    std::string filename_list_of_programs;
    for( int i=1; i< argc; i++){
        if( strcmp( argv[i], "-c" ) == 0 && i + 1 < argc ){
            set.max_cpus = atoi( argv[i+1] );
            properAssert( atoi( argv[i+1]) > 0 , "Num of cores need to be > 0 " );
            properAssert( set.max_cpus <= std::thread::hardware_concurrency() , "Cannot use more than " + std::to_string(std::thread::hardware_concurrency()) + " cores " );
            std::cout << KINFO "Using cores : " << set.max_cpus << KNRM << "\n"; 
        }
        if( strcmp( argv[i], "-m" ) == 0 && i + 1 < argc ){
            set.max_launched = atoi( argv[i+1] );
            properAssert( set.max_launched > 0 , "Num of programs need to be > 0 " );
            std::cout << KINFO "Max lunched: " << set.max_launched <<  KNRM << "\n"; 
        }
        if( strcmp( argv[i], "-p" ) == 0 && i + 2 < argc ){
            set.max_launched = atoi( argv[i+1] );
            properAssert( set.max_launched > 0 , "Num of programs need to be > 0 : " + std::to_string(set.max_launched) );
            filename_list_of_programs = argv[i+2];
            properAssert( fs::exists(filename_list_of_programs) , "Cannot find the file for candidates: " + filename_list_of_programs );
            std::cout << KINFO "Fuzzing programs with file: " << set.max_launched << " " << filename_list_of_programs << KNRM << "\n"; 
        }
        if( strcmp( argv[i], "-ow" ) == 0){
            properAssert( 0 == set.mode_ow_cont , "Mode is not 0: " + std::to_string(set.mode_ow_cont));
            set.mode_ow_cont = 1;
            std::cout << KINFO "Overwrite run " << KNRM << "\n"; 
        }
        if( strcmp( argv[i], "-cont" ) == 0){
            properAssert( 0 == set.mode_ow_cont , "Mode is not 0: " + std::to_string(set.mode_ow_cont));
            set.mode_ow_cont = 2;
            std::cout << KINFO "Continue run " << KNRM << "\n"; 
        }
    }

    std::string prog_name;  
    int pipe_main[2], pipe_side[2];
    static std::mt19937 mt      = std::mt19937(time(nullptr));


    setupSignalHandlers();
    setupMajor(argv[0], prog_name, pipe_main, pipe_side );

    // collect all program candidates for fuzzing
    std::vector<std::string> fuzz_candidates;
    collectFuzzCandidates( g_folder_fuzz_targets, fuzz_candidates  );
    std::cout <<"Total candidate programs:" << fuzz_candidates.size() << std::endl;

    // leave only the required programs if file is provided
    if( filename_list_of_programs.size() > 0 ){
        std::ifstream mf( filename_list_of_programs );
        std::string l;
        std::set<std::string> s;
        while( mf >> l )
            s.insert( g_folder_fuzz_targets + "/" + l );
        for( int i= fuzz_candidates.size()-1; i>=0; i--)
            if( ! s.contains(fuzz_candidates[i]) )
                fuzz_candidates.erase( fuzz_candidates.begin() + i ); 
        mf.close();  
    }

    createFuzzingContextes( fuzz_candidates, fctx );
    std::cout<<"Total evaluation programs: " << fctx.size() << std::endl;


    // adjust total time according to the number of binaries, time per binary, and number of cores
    if( set.mode == Run::testing || set.mode == Run::fuzz_compare ){
        set.max_time_to_run = std::min(uint(fctx.size()), set.max_launched) * set.time_per_binary / set.max_cpus ;
        properAssert( set.max_time_to_run > 0 ,"max_time_to_run is zero");
        std::cout   <<"Time to run: " << std::fixed << set.max_time_to_run 
                    << "  :  " << fctx.size() << " " << set.max_launched << " " << set.time_per_binary << " " << set.max_cpus << std::endl;
    }
    else
        set.max_time_to_run = -1;

    // output target programs to file (for inspection later)
    std::ofstream inspect_file("./currently_running.txt");
    for( auto &f: fctx )
        inspect_file << f->get_id()<<"\n";
    inspect_file.close();

    std::vector<FuzzingContext*> running;       // currently running
    std::vector<FuzzingContext*> stopped;       // waiting to be scheduled for run

    for( auto &fz: fctx ){
        // the state can also be killed if during the constructor did not 
        // find missing information. Thus the check
        if( fz->getState() == State::init ) 
            stopped.push_back( fz );
    }

    uint max_run_threads = set.max_cpus ; 

    // start some programs
    while( running.size() < max_run_threads && stopped.size() > 0 ) {
        int index = mt() % stopped.size();
        startOne( stopped[index], pipe_main, pipe_side  );
        running.push_back( stopped[index] );
        stopped.erase( stopped.begin() + index );
    }

    // timers mainly for profiling purposes 
    auto time_of_start          = std::chrono::system_clock::now();
    auto last_time_of_serial    = std::chrono::system_clock::now();
    auto last_time_of_log_output= std::chrono::system_clock::now();
    auto last_time_of_fix_procs = std::chrono::system_clock::now();
    auto last_time_prev_start   = std::chrono::system_clock::now();
    auto last_time_bucket_check = std::chrono::system_clock::now();
    auto last_time_pick_random  = std::chrono::system_clock::now();
    auto last_time_crash_report = std::chrono::system_clock::now();



    Debug d;
    std::ofstream log_fix, log_fctx;
    log_fix.open("lfix.log",std::ios::out);
    log_fctx.open("lfctx.log",std::ios::out);
    double ema_time_slice = set.time_slice_secs;
    double ma_time_slice  = set.time_slice_secs;
    uint ma_cnt{0};

    std::vector< double > gs{ 0.9, 0.99, 0.999};
    std::map< double, std::vector<double>  > gams;
    for( auto g: gs )
        gams.insert( {g, std::vector<double>{300.0, 0, 1.0, 1.0} } );
    double last_gam = -1;
    uint last_ind = 0;
    double prev_cov = 0; 
    std::uniform_real_distribution<float> d01(0,1);


    std::future< std::tuple<std::set<uint>, double >> fut;  // to launch separate thread that will be fixing processes that misbehave
    bool fut_first{true};
    if( set.use_var_epsilon )
        changeIncrementEpsilon( (set.max_time_to_run > 0 ? set.max_time_to_run : 30000)  / set.secs_between_pick_random ); 

    // if -cont then make sure adjustment is done at least once
    if( 2 == set.mode_ow_cont ){
        for( auto t: fctx)
            t->getMab().adjustToNewGamma();
    }

    while(true) {

        auto tmp_time_rstart = std::chrono::system_clock::now();

        // time slices can be too small, so printing too much
        // can have significant overhead. 
        // so, print only after secs_between_prints time interval has passed.
        static auto time_prev_print = std::chrono::system_clock::now();
        int supress_fd = -1;
        if( set.secs_between_prints > 0 && timeElapsedMSecs( time_prev_print ) > 1000 * set.secs_between_prints )
            time_prev_print = std::chrono::system_clock::now();
        else
            supress_fd = supress_stdout();
            
        // print information about the states of all evaluated programs
        std::map<State,uint> scnt;
        for( auto &t: fctx )
            scnt[t->getState()]++;
        std::cout << KINFO "Number of ";
        for( auto &s: scnt )
            std::cout << getStateString( s.first ) <<" / ";
        std::cout<<" : ";
        for( auto &s: scnt )
            std::cout << s.second  <<" ";
        std::cout<<"\n";
        // print info about scheduler
        std::cout << KINFO << "Scheduler  " << getEnvironmentVariable("BOIAN_SCHEDULER") << "   :   " ;
        std::cout << " Use CPUs  " << set.max_cpus << "   :   ";
        // stop the fuzzing if time_to_run is set and it expired
        std::cout   << KINFO<<"Time to run  " << std::fixed 
                    << "  " << std::setprecision(1) << timeElapsedMSecs(time_of_start) /1000 
                    << "  " << std::setprecision(1) << set.max_time_to_run << KNRM <<std::endl;
        if( set.max_time_to_run > 0  && timeElapsedMSecs( time_of_start ) > set.max_time_to_run * 1000 ){
            properShutdown();
            exit(0);
        }
        // print info about coverage
        uint tcov = 0, tedg=0;
        for(auto &t: fctx){ 
            tcov+= t->get_shm()->tot_coverage; 
            tedg+= t->get_shm()->tot_edges; 
        }
        std::cout << KINFO "Total coverage: " << std::dec<< tedg << " " << tcov << KNRM << std::endl;

        // serialize 
        if( timeElapsedMSecs( last_time_of_serial ) > set.secs_between_serialize * 1000 ){
            for( auto &t: running )
                t->serialize();
            last_time_of_serial  = std::chrono::system_clock::now();
        }


        // pick random instead of only MAB if bottom MAB perform not better than random 
        if(     set.use_var_epsilon 
            &&  timeElapsedMSecs( time_of_start ) > 300 * 1000
            &&  timeElapsedMSecs( last_time_pick_random ) > set.secs_between_pick_random * 1000 
        ){
            last_time_pick_random  = std::chrono::system_clock::now();
            changeEpsilon( true );
        }

        // fix processes
        if( timeElapsedMSecs( last_time_of_fix_procs ) > set.secs_between_fix_procs * 1000 ){
            last_time_of_fix_procs  = std::chrono::system_clock::now();
            if( fut_first || (fut.valid() && fut.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) ) {
                if( !fut_first ){
                    auto _res = fut.get();
                    auto &termed = std::get<0>(_res);
                    if ( termed.size() > 0 ){
                        for( auto f: fctx ){
                            if( f->getState() != State::killed &&
                                termed.contains( f->get_shm()->id )
                            ){
                                    f->fuzzKill();
                                    f->get_shm()->state = State::killed;
                                    std::cout<<KINFO <<"Stop prog: " << f->get_id() <<" " << f->get_file_binary_only()
                                        << KNRM << std::endl;
                            }
                        }
                    }
                    // time
                    d.debug_time_fix_proc += std::get<1>(_res);
                }
                fut = std::async( std::launch::async, fixProcesses, std::cref(prog_name), std::ref(log_fix) );
            }
            fut_first = false;
        }
                

        // let it run for time slice seconds
        std::this_thread::sleep_for(std::chrono::milliseconds( static_cast<uint>(set.time_slice_secs * 1000) ));

        // for each each fuzzing program, check if needs to change between AFL fuzzing, showmap, symcc
        auto tmp_time_step = std::chrono::system_clock::now();    
        stepFuzzOrUpdateMap( running, stopped, pipe_main, pipe_side );
        d.debug_time_stepfuzz += timeElapsedMSecs( tmp_time_step );

        
        for( int i= running.size()-1; i>=0; i--)
            if ( running[i]->getState() == State::killed  || running[i]->getAction() == Action::out ){
                running[i]->get_shm()->state = State::killed;
                running.erase( running.begin() + i );
            }

        for( int i= stopped.size()-1; i>=0; i--)
            if ( stopped[i]->getState() == State::killed  || stopped[i]->getAction() == Action::out ){
                stopped[i]->get_shm()->state = State::killed;
                stopped.erase( stopped.begin() + i );
            }
            

        auto tmp_time_evsch = std::chrono::system_clock::now();    

        // evict one from running to schedule new
        if( stopped.size() > 0 ) {            
            evict( 1, running, stopped );
            schedule( 1, running, stopped, pipe_main, pipe_side );
        }

        // evict if more running then available cpus
        evict( running.size() -  max_run_threads , running, stopped );

        // schedule new depending on how many free cores there are 
        schedule( max_run_threads - running.size(), running, stopped, pipe_main, pipe_side );

        d.debug_time_debug_time_evsch += timeElapsedMSecs( tmp_time_evsch );

        if( set.use_MAB_schedule && set.use_dynamic ) {

            if( ( ! scnt.contains(State::init) || double(scnt[State::init])/fctx.size() < 0.25 )                // sufficient initalized
                && timeElapsedMSecs( last_time_bucket_check ) > 10 * 1000   
                && timeElapsedMSecs( time_of_start ) > 300 * 1000 )  
            {

                double gsecs = timeElapsedMSecs( last_time_bucket_check ) / 1000;
                double tcovs = 0;
                for(auto &t: fctx) 
                    tcovs+= t->get_shm()->tot_coverage; 
                auto gcovs = tcovs - prev_cov;
                if( last_gam > 0 ){
                    double emaC = 0.75;
                    gams[last_gam][0] = emaC        * gams[last_gam][0] + 
                                        (1.0-emaC)  * gcovs/gsecs;
                    gams[last_gam][2] += gcovs;
                    gams[last_gam][3] += gsecs;
                }
                
                last_time_bucket_check  = std::chrono::system_clock::now();
                prev_cov                = tcovs; 

                auto best_gam = gs[0];
                for( auto &[k,v]: gams ){
                    if( v[0] > gams[best_gam][0] )
                        best_gam = k;
                }
                if(  d01(mt) < 0.25 )
                    best_gam = gs[ mt() % gs.size() ];
                // all this below is actually ignored, the idea did not work well, so 
                // instead use just rotation of gamma

                //best_gam = last_gam >= 0 ? (last_gam + 1)% gams.size() : 0; 
                last_ind = (last_ind + 1) % gs.size();
                if ( !set.use_var_epsilon )
                    last_ind = 0;
                best_gam = gs[ last_ind ];

                gams[best_gam][1] += 1;
                last_gam = best_gam;
                setGamma( best_gam );
                
                for( auto t: fctx)
                    t->getMab().adjustToNewGamma();
            }
        }



        // if no running programs, stop  
        if( running.empty() ) {
            if( supress_fd >= 0 )
                resume_stdout( supress_fd );
            break;
        }

        d.debug_time_tot += timeElapsedMSecs( tmp_time_rstart ) - (set.time_slice_secs * 1000);

        // debug info into file or screen
        if( set.secs_between_log_outputs > 0 && timeElapsedMSecs( last_time_of_log_output ) > 1000 * set.secs_between_log_outputs ){
            last_time_of_log_output    = std::chrono::system_clock::now();
            log_fctx  << "\nEpsilon : " << std::setprecision(5)<<getEpsilon() << std::endl;
            for( auto &t: fctx){
                log_fctx 
                    <<std::setw(4)<<getActionString(t->getAction())
                    <<" " << t->get_has_afl()<<t->get_has_sym() 
                    <<" " << std::setw(4)<<getStateString(t->getState())
                    <<" " << std::setw(3)<<t->getNumTC()
                    <<" " << std::fixed << std::setw(10) << std::setprecision(6) 
                    << t->getMab().debug(0,0 ) 
                    <<" " << t->getFolderRoot()
                    << std::endl;
            }
            log_fctx 
                    << "Times: " << std::setprecision(1)
                    << " "      << d.debug_time_fix_proc/1000
                    <<" "       << d.debug_time_readafl/1000
                    <<"  "      << d.debug_time_stepfuzz/1000
                    <<" "       << d.debug_time_multicore/1000
                    <<" "       << d.debug_time_debug_time_evsch/1000
                    <<" :   "   << d.debug_time_tot/1000 
                    << " "      << timeElapsedMSecs(time_of_start)/1000
                    <<std::endl;

        }


        std::cout   <<"Times: " << std::setprecision(1)
                    <<" "       << d.debug_time_fix_proc/1000
                    <<" "       << d.debug_time_readafl/1000
                    <<"  "      << d.debug_time_stepfuzz/1000
                    <<" "       << d.debug_time_multicore/1000
                    <<" "       << d.debug_time_debug_time_evsch/1000
                    <<" :  "    << d.debug_time_tot/1000 
                    <<std::endl;


        auto actual_time_slice = timeElapsedMSecs(last_time_prev_start) /1000;
        ema_time_slice = 0.95 * ema_time_slice + 0.05 * actual_time_slice;
        ma_time_slice  += actual_time_slice;
        ma_cnt         += 1;

        // crash report
        if( Run::search == set.mode 
            && timeElapsedMSecs( last_time_crash_report ) > 60 * 1000 
        ){
            last_time_crash_report  = std::chrono::system_clock::now();
            std::vector< std::pair< uint, std::string> > crashes; 
            for( auto t: fctx )
                if( t->getNoCrashes() > 0 )
                    crashes.push_back( {t->getNoCrashes()-1, t->getCrashFolder()});

            try {
                std::ofstream log_crashes("lcrashes.log", std::ios::trunc);
                if(log_crashes.is_open() ){
                    for( const auto &a: crashes)
                        log_crashes << std::setw(6) << a.first << " " << a.second << std::endl;
                    log_crashes << "\nTotal: " << crashes.size() << std::endl;
                    log_crashes.close();
                }
                else {
                    throw "File could not be opened.";
                }
            }
            catch (const char* error) {
               std::cerr << "Error: " << error << std::endl;
            }


        }



        last_time_prev_start   = std::chrono::system_clock::now();

        // redirect file descriptor for stdout
        if( supress_fd >= 0 )
            resume_stdout( supress_fd );

    }

    properShutdown();

    return 0;
}
