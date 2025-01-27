#ifndef PARAMS_H
#define PARAMS_H

#include <filesystem>
#include <fstream>
#include <cmath>
#include <vector>
#include <iostream>

namespace fs = std::filesystem;

std::string getEnvironmentVariable(const std::string &varName, bool throwIfNotFound = true );

static const std::string g_folder_fuzz_targets      = getEnvironmentVariable("BOIAN_FUZZ_TARGETS");

static const std::string kFolderAFLPPShowmap        = getEnvironmentVariable("BOIAN_AFLPP");
static const std::string kFilepathAFLPPShowmap      = kFolderAFLPPShowmap + "/afl-showmap";
static const std::string kFolderAFL                 = getEnvironmentVariable("BOIAN_AFL");
static const std::string kFolderAFLPP               = getEnvironmentVariable("BOIAN_AFLPP");
static const std::string kFolderHonggfuzz           = getEnvironmentVariable("BOIAN_HONGGFUZZ", false );
static const std::string kFileQemu                  = kFolderHonggfuzz + "/qemu_mode/honggfuzz-qemu/x86_64-linux-user/qemu-x86_64";

static const std::string kFolderShowmapSuffix       = "/showmap_test";
static const std::string kAFLTCQPathSuffix          = "/symcc/queue/";
static const std::string kFuzzerSuffix              = "/afl-fuzz"; 

static const std::string kProcEnvProcess            = "fuzzerDistinctProc=";
static const std::string kBinModeSwitch             = "-Q";

static const char kSendAFL                          = 11;
static const char kSendAFLPP                        = 12;
static const char kSendHonggfuzz                    = 13;
static const char kSendShow                         = 22;
static const char kSendSym                          = 33;
static const char kSendOk                           = 77;
static const char kSendEnd                          = 88;
static const char kSendError                        = 99;

static const uint kMaxMemUsageInMB                  = 1000;  // 1 GB max
static const uint kMaxCPUUsage                      = 200;   // 200% CPU between two measurement points in time
static const uint kMaxDebugSize                     = 1000000;
static const uint kLargeNumberForScore              = 999;
static const uint kMaxPipeBufferSize                = 1<<10;


static const double kInitialCoverage                = 5.0;
static const double kInitialTime                    = 0.1;
static const double kMinSecsRun                     = 5.0; 

static const uint   kBucketWindowInit               = 5;
static const double kBucketsSecsLength              = 1.0;
static const double kDynamicStartGamma              = 0.9;
static const double kDynamicC                       = 0.1;

// run mode (explore, testing, fuzz_compare, search)
// explore:     used to find among all programs which can be fuzzed, i.e. for which 
//              AFL can find some **additional** coverage besides the once produced
//              by the provided testcases
// testing:     compare fuzzing regimes, i.e. MAB, dynamic, var_epsilon
// fuzz_compare:compare different fuzzers, e.g. AFL++ vs Honggfuzz 
// search:      used to find bugs with AFL++ 
enum class Run{explore, testing, fuzz_compare, search}; 
// in explore mode:
//      Once additional coverage is increased, stop fuzzing 
// in testing mode:
//      1.  do not run binaries without AFL instrumentation 
//          because afl-qemu misbehaves, needs to be killed and this biases the exact measurements
//      2.  take only 1 testcase to reduce variance

enum class Fuzzer{ AFL, AFLPP, Honggfuzz };

struct Settings{

    Settings(){
        if( Fuzzer::AFLPP == fuzzer){
            folder_fuzzer           = kFolderAFLPP;
            filepath_fuzzer         = folder_fuzzer + "/afl-fuzz" ;

        } 
        else if( Fuzzer::AFL == fuzzer) {
            folder_fuzzer           = kFolderAFL;
            filepath_fuzzer         = folder_fuzzer + "/afl-fuzz" ;
        } 
        else if( Fuzzer::Honggfuzz == fuzzer){ 
            folder_fuzzer           = kFolderHonggfuzz;
            filepath_fuzzer         = folder_fuzzer + "/honggfuzz" ; 
            kAFLTCMPathSuffix       = "/honggfuzz/";
            foldCrashes             = "/honggfuzz-crashes/";
        }

        std::cout<<"Fuzzer is " << folder_fuzzer << "\n";
    }

    Run mode                            = Run::testing; 

    bool use_var_epsilon                = getEnvironmentVariable("BOIAN_SCHEDULER") == "boian";
    bool use_dynamic                    = use_var_epsilon || getEnvironmentVariable("BOIAN_SCHEDULER") == "discounted"; 
    bool use_MAB_schedule               = use_dynamic || getEnvironmentVariable("BOIAN_SCHEDULER") == "mab";

    Fuzzer fuzzer                       = Fuzzer::AFLPP;
    
    bool use_symcc                      = false;

    // no cpu to use
    uint max_cpus                       = std::stoul(getEnvironmentVariable("BOIAN_USE_CPUS"));

    // avg time per single program
    double time_per_binary              = 60 * std::stoul(getEnvironmentVariable("BOIAN_MINUTES_PER_TARGET"));


    // duration of one time slice
    double time_slice_secs              = 0.1; 

    // max programs to fuzz
    uint max_launched                   = 100000; 

    uint stop_if_crashes                = 1000; // stop fuzzing this program it produced more than this crashes

    // min secs to fuzz one program
    double time_min_run_secs            = 5.25 * time_slice_secs ; // run at least 5 time slices 
    
    // total secs to run the whole program (if negative, then ignore)
    double max_time_to_run              = -1; //10*3600 ;  

    // mode (overwrite, continue, etc)
    int mode_ow_cont                    = 0;

    // number of TC to store in AFL folder as initial 
    uint max_testacases                 = 10; 

    // control output
    bool output_execve{true};

    // store output of AFL, showmap, symcc to file
    bool save_output_of_fuzzers         = true;

    // mute output of actual programs
    bool mute_programs_output           = true;

    std::string folder_fuzzer           ;
    std::string filepath_fuzzer         ; 
    std::string filepath_fuzzer_showm   = kFilepathAFLPPShowmap;

    std::string kAFLTCMPathSuffix          = "/aflm/queue/";
    std::string foldCrashes                = "/aflm/crashes/";
    

    // times (in seconds) to execut programs and similar
    double max_time_afl                 = 0.75;
    double max_time_showmap             = 0.75;
    double max_time_symcc               = 15;         
    double max_time_consecutive_symcc   = 20.0; 
    double min_time_pause_symcc         = 5;       // to make sure AFL has chance to read the new TC

    double secs_between_serialize       = 75;
    double secs_between_prints          = 0.5;
    double secs_between_showsymcc       = 1.0;
    double secs_between_fix_procs       = 3; 
    double secs_between_log_outputs     = 60.0;
    double secs_between_read_AFL_stats  = 10.0;
    double secs_between_cpu_util        = 1.0;
    double secs_between_pick_random     = 60;
    double secs_between_no_crashes      = 10; 


    // wait times to start certain procedures
    double secs_wait_to_start_showmap   = 3; 
    double secs_wait_to_start_symcc     = 20;            
    double secs_wait_to_start_multicore = 60;
    double secs_wait_term_if_only_tc    = 30; // stop fuzzing if only initial testcases 
    double secs_wait_tf_exec_per_sec    = 30; // wait to start incorporating exec_per_sec factor
    double secs_wait_tf_total_edges     = 30; // wait to start incorporating total_edges

    // -m param passed to AFL
    std::string afl_mem_limit           = "none" ;

    uint max_file_size_mb               = 50;  // limit the size of created files (becuase some of them will create GBs files)

    uint max_no_bootstrap_trials       = 5; // how many times to try to bootstrap before give up (it can fail if too many processes running simultaneously)
};

extern Settings set;

// colors
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KERR  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KINFO "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KSEC  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KIMP  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


#endif

// change hongfuzz installation
// 1. comment setsid ( so signals send to fuzzer propagate to children)
// 2.  .sa_flags   = SA_NOCLDWAIT, (so no zombies)
