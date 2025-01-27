
#include "misc.h"
#include "scheduler.h"
#include "mab.h"
#include "class_fuzzing_context.h"
#include "fork_servers.h"

// global vars because they are accessed through signal handler functions 
static int child_pid    = -1;
static pid_t g_main_pid = 0;
static Action g_current_action;

extern std::vector<FuzzingContext*> *ptr_fctx;


bool isMainThread() {
    return g_main_pid == gettid();
}

void setMainThread() {
    g_main_pid  = gettid();
}

void setCurrentAction( const Action a){
    g_current_action = a;
}


// set timer for parent process to waitpid for child to finish
int timeChild( const pid_t pid, const double seconds ){
    child_pid = pid;
    static struct itimerval it;
    it.it_value.tv_sec  = int64_t( seconds );                       
    it.it_value.tv_usec = int64_t( seconds * 1000000) % 1000000;
    setitimer(ITIMER_REAL , &it, NULL);     
    int status;
    auto pp = waitpid( pid, &status, 0 );

    std::cout<<"timeChild : " << pp <<" " << status << " : " ;
    if (WIFEXITED(status)) 
        std::cout<< " Exited with status "<< WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) 
        std::cout<< "  Was terminated by signal " << WTERMSIG(status);
    else 
        std::cout << "  Changed state, but its status could not be determined";
    std::cout<<std::endl;

    child_pid = -1;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
    return status;
}

bool isProcessValid( const pid_t pid ){
    return 0 == kill( pid, 0 );
}


// kill all spun fuzzers and free the shared memory
void properShutdown(  [[maybe_unused]]  const std::string &message) {
    
    std::cout << KINFO << "Proper shutdown: "<<ptr_fctx->size()<<"  :  " <<gettid()<<"  :  " << message<<"\n" << KNRM<<std::endl; ;
    for(auto fz: *ptr_fctx ){
        fz->fuzzKill();
        fz->freeShm();
    }
    
}

// if assertion fails then first kill all processes, free memory and then exit
void properAssert( bool expr, const std::string &message ){
    if( !expr){
        std::cout << KERR << "<error> " << message << KNRM << std::endl;  
        // if main process then just shutdown
        if( getpid() == g_main_pid )
            properShutdown();
        // else send signal to main process
        else
            terminateProgram();
        exit(0);
    }
}

// send signal to main process to terminate the program
void terminateProgram( const std::string message ){
    std::cout << "terminate message:" << message << std::endl;
    kill( g_main_pid, SIGUSR1);
}

// if it is the main process then terminate the program, otherwise just exit the process
void handleTermSig( [[maybe_unused]] int sig) {
    std::cout<<"handleTermSig" <<std::endl;
    if( isMainThread() )
        properShutdown("handleTermSig");
    else{
        std::cout<<"Terminate side thread: " << getpid() << std::endl;
    }
    exit(0);
}

void handleTimeout([[maybe_unused]] int sig) {
    std::cout<< KINFO << "Timeout on " << getActionString(g_current_action)  
            << " " << getpid()<< "  " << child_pid << std::endl  << KNRM ;
    if (child_pid > 0) 
        kill(child_pid, SIGKILL /*SIGTERM */ );
}

void handleSigUsr(int signo) {
    if (signo == SIGUSR1) {
        //std::cout<<"Received SIGUSR1"<<std::endl;
        //properAssert(0, "terminated");
    }
}


void setupSignalHandlers()  {


    struct sigaction sa;
    sa.sa_handler     = NULL;
    sa.sa_flags       = SA_RESTART;
    sa.sa_sigaction   = NULL;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler     = handleTermSig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    sigemptyset(&sa.sa_mask);
    sa.sa_handler     = handleTimeout;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGVTALRM, &sa, NULL);
    sigaction(SIGPROF, &sa, NULL);

    //  no zombies upon termination
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, NULL);


    // so child can kill the main program (mainly for debug)    
    signal(SIGUSR1, handleSigUsr);

}

int getProcStatus( pid_t pid) {
    
    int status;
    pid_t ret_pid = waitpid(pid, &status, WNOHANG | WUNTRACED | WCONTINUED);

    if (ret_pid == pid) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return 0; // Zombie process
        } else if (WIFSTOPPED(status)) {
            return 2; // Stopped process
        } else if (WIFCONTINUED(status)) {
            return 1; // Running process
        }
    } else if (ret_pid == 0) {
        return 1; // Running process
    } else {
        if (errno == ECHILD) {
            return -1; // Process does not exist or not a child of the calling process
        } else {
            perror("waitpid");
            return -1; // Error
        }
    }

    return -1; // Error
}

bool reapChildProc( pid_t pid ){
    int status;
    return waitpid(pid, &status, WNOHANG) > 0;
}

pid_t getChildPid( pid_t ppid ) {
    PROCTAB *proc = openproc(PROC_FILLSTAT);
    while (proc_t *proc_info = readproc(proc, nullptr)) {
        if (proc_info->ppid == ppid) 
            return proc_info->tgid;
        freeproc(proc_info);
    }
    return 0;
}

pid_t getHonggChild( pid_t target_pid ){

    static const std::string kHonggChild =  "hongg_child_pid";
    static const size_t n = kHonggChild.size();

    proc_t proc_info;
    memset(&proc_info, 0, sizeof(proc_info));
    pid_t pids[2] = {target_pid, 0 } ;
    PROCTAB* proc_tab = openproc(PROC_FILLENV | PROC_PID, pids);
    while (readproc(proc_tab, &proc_info) != NULL) {

        int i = 0;
        while (proc_info.environ[++i]) {
            std::cout<<"proc_info:"<<proc_info.environ[i]<<std::endl;
        }

        if( proc_info.environ != nullptr ) 
            for( int i=0; proc_info.environ[i]; i++){
                if( strncmp( proc_info.environ[i], kHonggChild.c_str(), n ) == 0 ){ 
                    uint id = atoi( proc_info.environ[i] + n ); 
                    return id;
                }
            }



        std::cout << "Process information for PID: " << target_pid << std::endl;
        std::cout << "Command: " << proc_info.cmd << std::endl;
        std::cout << "State: " << proc_info.state << std::endl;
        std::cout << "User time: " << proc_info.utime << std::endl;
        std::cout << "System time: " << proc_info.stime << std::endl;
        std::cout << "Memory size: " << proc_info.size << " kB" << std::endl;
        std::cout << "Environ: " << proc_info.environ << std::endl;
    } 

    closeproc(proc_tab);
    return 0;
}


// set soft affinity to process
void setAffinity(pid_t pid ){
    cpu_set_t mask;
    CPU_ZERO(&mask);
    for( uint i=0; i< set.max_cpus; i++)
        CPU_SET(i, &mask);

    properAssert( sched_setaffinity(pid, sizeof(mask), &mask) != -1, "Error setting CPU affinity");
}

void setAffinity(){ setAffinity( getpid() ); }

// fork and immediately set soft affinity to child process
pid_t properFork() {
    auto pid = fork();
    properAssert( pid >= 0, "fork() failed");

    if ( 0 == pid )
        setAffinity();
    return pid;
}