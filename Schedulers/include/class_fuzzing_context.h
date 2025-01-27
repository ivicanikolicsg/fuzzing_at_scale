#ifndef CLASS_FUZZING_CONTEXT_H
#define CLASS_FUZZING_CONTEXT_H

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include <unordered_set>
#include <functional>
#include <condition_variable>
#include <cmath>
#include <map>
#include <shared_mutex>
#include <regex>

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/export.hpp>
#include <boost/serialization/split_member.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/unordered_set.hpp>

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


#include "misc.h"
#include "mab.h"
#include "add_structs.h"
#include "system-stuff.h"



class FuzzingContext{
public:

    FuzzingContext( const FuzzingContext & )  = delete;
    FuzzingContext( std::string folder_target_prog, int mode_ow_cont );
    ~FuzzingContext();

    std::string getFolderRoot() const ;
    std::string getFolderInput() const ;
    std::string getFolderOutput() const ;
    std::string getFolderOriginalTC() const ;
    std::string getFolderFuzzerTCMaster() const ;
    std::string getFolderFuzzerTCSymcc() const ;
    std::string getFolderMisc() const ;
    std::string getFuzzBinary() const;
    std::vector<std::string> getArgs() const ;
    State getState() const ;
    Action getAction() const ;
    pid_t getPid() const ;
    MAB &getMab() ;
    std::string get_folder_showmap_test() const ;
    std::string get_folder_target_prog() const;
    std::string get_folder_symcc() const ;
    std::string get_folder_misc() const ;
    std::string get_folder_debug() const ;
    std::string get_file_binary_only() const ;
    std::string get_file_binary_afl() const ;
    std::string get_file_symcc_input() const ;
    std::string get_file_sim_input() const ;
    std::string get_file_binary_symcc() const ;
    std::string get_param_binary() const ;
    std::string get_debug_afl_file() const ;
    std::string get_debug_showmap_file() const ;
    std::string get_debug_sym_file() const ;
    std::string get_debug_sym_showmap_file() const ;
    std::string get_file_sim_output() const ;
    double getCurScore() const ;
    double getCurFuzzTime() const;


    int get_shm_id() const { return shm_id;}
    auto get_shm() const { return shm;}
    auto get_symcc_args() const { return symcc_args;}
    auto getTimeScheduled() const { return time_of_schedule; }
    auto get_id() const { return id;}
    auto getTimeFuzzed() const {  return time_total_fuzz; }


    void setPid( pid_t val );
    void setPidShowmap( pid_t val );
    void setPidSym( pid_t val );
    void setAction ( Action act );

    static void set_add_scoreStatic( Shared_memory *shmm, uint topup_score, uint topup_cover );
    void set_add_score( uint topup_score, uint topup_cover );
    static uint get_add_scoreStatic(  Shared_memory *shmm  );
    uint get_add_score( ) ;
    static uint get_coverageStatic(  Shared_memory *shmm  );
    uint get_coverage( ) ;

    
    void setNumTC( uint a ) { num_tc += a;}
    auto getNumTC( ) const { return num_tc;}

    void set_time_of_start_symcc();
    void set_time_of_pause_symcc();
    void set_time_of_stop_symcc();
    double get_symcc_running_time();
    double get_symcc_pause_time();
    double get_symcc_start_stop_diff();


    bool fuzzInit();
    bool fuzzCont();
    void fuzzStop();
    void fuzzKill();
    static void fuzzKillStatic(Shared_memory *shm);

    void switchToFuzzing() ;
    void freeShm();


    bool isGoodTC( const std::string &fpath );

    std::vector<std::string> getShowmapCandidates();

    std::vector<std::string> getSymCandidates();
    
    void printStats( std::string title);
    std::string debug();    
    std::string debugAdd();

    static std::string getIdFromFolder( std::string fold ) {
        std::regex pattern("^.*/");
        std::smatch match;

        if (std::regex_search(fold, match, pattern)) 
            return match.suffix();        
        return "0";
    }

    static std::string getBinaryFromFolder( std::string fold ) {
        std::string filepath_fuzz_info {fold + "/fuzz_info.txt"} ;
        if( folderFileExists(filepath_fuzz_info) ){
            std::ifstream f(filepath_fuzz_info);
            std::string file_binary_only;
            getline(f,file_binary_only);
            std::regex pattern("^.*/");
            std::smatch match;
            if (std::regex_search(file_binary_only, match, pattern)) 
                return match.suffix();        
            f.close();
        }  
    
        return "some_unknown_binary";
    }

    void serialize() ;
    void deserialize();

    void stopAFL(){
        killpg( getpgid(shm->afl_pid), SIGSTOP  ) ;        
    }

    void updateScoreState( double time_passed );

    void set_shm( Shared_memory *nshm ){ shm = nshm ; }


    auto get_has_afl() const { return has_afl; }
    auto get_has_cmp() const { return has_cmp; }
    auto get_has_sym() const { return has_sym; }


    std::string get_ld_lib() const { return ld_lib; }
    std::string get_cwd_lib() const { return cwd_lib; }

    auto get_time_last_showmap() const { return time_last_showmap; }
    void set_time_last_showmap(){ time_last_showmap = std::chrono::system_clock::now(); };

    auto get_time_last_symcc() const { return time_last_symcc; }
    void set_time_last_symcc(){ time_last_symcc = std::chrono::system_clock::now(); };

    static std::string produce_debug_afl_file(std::string &folder_target_prog)  { 
        return folder_target_prog + "/debug/afl_fuzz.out";
    }
    static std::string produce_debug_showmap_file(std::string &folder_target_prog)  { 
        return folder_target_prog + "/debug/showmap_fuzz.out";
    }
    static std::string produce_debug_sym_file(std::string &folder_target_prog)  { 
        return folder_target_prog + "/debug/sym_fuzz.out";
    }
    static std::string produce_folder_symcc(std::string &folder_target_prog)  { 
        return folder_target_prog+"/fuzz_output/symcc";
    }
    static std::string produce_folder_misc(std::string &folder_target_prog)  { 
        return folder_target_prog+"/misc";
    }
    static std::string produce_folder_showmap_test(std::string &folder_target_prog)  { 
        return produce_folder_misc(folder_target_prog)+kFolderShowmapSuffix ;
    }
    static std::string produce_file_symcc_input(std::string &folder_target_prog)  { 
        return produce_folder_misc(folder_target_prog)+"/symcc_input" ;
    }


    static void switchToFuzzingStatic(Shared_memory *shm);

    bool AFLSetupIsDone(){
        if( afl_setup_done ) return true;

        const uint min_file_size = 32;
        fs::path file_path(folder_target_prog + "/debug/afl_fuzz.out");
        if( folderFileExists(file_path) && fs::file_size(file_path) >= min_file_size )
            afl_setup_done = true;
        return afl_setup_done;        
    }

    void increaseNoBootstrap(){
        no_bootstraps++;
    }
    auto get_no_bootstraps() const { return no_bootstraps; }

    void aflReinit(){

        // reinit state
        shm->state = State::init;
        // rename old afl log
        fs::rename(get_debug_afl_file(), get_debug_afl_file()+"-"+std::to_string(get_no_bootstraps()));
        // remove AFL folder
        std::string afl_fold = getFolderOutput()+"/aflm";
        if( folderFileExists( afl_fold )  ){
            try{
                fs::remove_all( fs::path{afl_fold} ); }
            catch (const std::exception& e) {
                std::cerr << "Caught remove_all exception: " << e.what() << std::endl; }
        }
        try{
            fs::create_directories( fs::path{afl_fold} );}
        catch (const std::exception& e) {
            std::cerr << "Caught create_directories exception: " << e.what() << std::endl; }

        shm->showmap_session    = 0;
        num_tc                  = 0;
    }


    void honggReinit(){
        // reinit state
        shm->state = State::init;
        // copy all found files
        copyFiles( folder_fuzz_output+"/honggfuzz", folder_fuzz_input );
    }

    uint getNoCrashes(){
        if( timeElapsedMSecs( time_last_no_crashes ) > 1000 * set.secs_between_no_crashes ){
            time_last_no_crashes = std::chrono::system_clock::now();
            no_crashes = countFilesInDirectory(folder_crashes);
        }
        return no_crashes;
    }

    std::string getCrashFolder() const { return folder_crashes; };


 private:

    std::string id;
    std::string folder_target_prog;
    std::string folder_fuzz_input ;
    std::string folder_fuzz_output;
    std::string folder_symcc;
    std::string folder_original_tc;
    std::string folder_debug;
    std::string folder_crashes;
    std::string folder_fuzzer_tc_master, folder_fuzzer_tc_symcc;
    std::string folder_misc;
    std::string folder_showmap_test;
    std::string file_binary_afl, file_binary_afl_true, file_binary_cmp, file_binary_symcc, file_binary_hongg, file_binary_only;
    std::string file_symcc_input, file_sim_input, file_sim_output;
    std::string file_serial;
    std::string param_binary;
    std::vector<std::string> afl_master_args, symcc_args;
    std::chrono::time_point<std::chrono::high_resolution_clock> time_of_schedule;

    double time_total_fuzz{0.00001};

    uint num_tc{0};
    std::unordered_set<std::string> showmap_passed;
    std::unordered_set<std::string> symcc_passed;

    // multi armed bandit data
    MAB mab;

    // shared memory
    int shm_id{0};
    Shared_memory *shm{nullptr};

    std::string afl_fold{""};
    std::string def_fold{""};
    std::string ld_lib{""};
    std::string cwd_lib{""};
    bool only_gcc{true}, has_afl{false}, has_afl_true{false}, has_sym{false}, has_cmp{false}, has_hongg{false};

    fs::file_time_type last_write_showmap, last_write_sym;

    std::chrono::time_point<std::chrono::system_clock> time_last_showmap, time_last_symcc, time_last_no_crashes;

    bool afl_setup_done{false};
    uint no_bootstraps{0};

    uint no_crashes{0};

};


#endif