#ifndef SYSTEM_STUFF_H
#define SYSTEM_STUFF_H


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
#include <sys/mman.h> 

#include "add_structs.h"


void setMainThread();
bool isMainThread();

void setCurrentAction( const Action a);

bool isProcessValid( const pid_t pid );


int timeChild( const pid_t pid, const double seconds );
void properShutdown( const std::string &message="");
void properAssert( bool expr, const std::string &message = "");
void terminateProgram(std::string message = "[empty]");
void handleTermSig( [[maybe_unused]] int sig);
void handleTimeout([[maybe_unused]] int sig);
void handleSigUsr(int signo);
void setupSignalHandlers();
pid_t properFork();
void setAffinity();
int getProcStatus( pid_t pid);
bool reapChildProc( pid_t pid );
pid_t getChildPid( pid_t ppid );
pid_t getHonggChild( pid_t target_pid );


template <class T, size_t E>
void allocateShared( T **p, int &shm_id ) {
    shm_id = shmget(IPC_PRIVATE, sizeof(T) * E, IPC_CREAT| IPC_EXCL | 0600 );
    //std::cout<<"allocated:"<<shm_id<<":"<< (sizeof(T) * E) << std::endl;
    if( shm_id == -1 ){
        std::cout<<"shmget failed for type " << typeid(T).name()<<" " << strerror(errno) <<"\n";
        properShutdown();
        exit(0);
    }
    *p = (T *) shmat( shm_id, NULL, 0 );
        
    madvise( *p,sizeof(T) * E, MADV_DONTFORK);

}


#endif