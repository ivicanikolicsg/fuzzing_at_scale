
#include <iostream>
#include <functional>
#include <numeric>      
#include <atomic>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "class_fuzzing_context.h"
#include "misc.h"
#include "scheduler.h"



FuzzingContext::FuzzingContext( std::string folder_target_prog, int mode_ow_cont ):
    folder_target_prog(folder_target_prog),
    folder_fuzz_input(folder_target_prog+"/fuzz_input"),
    folder_fuzz_output(folder_target_prog+"/fuzz_output"),
    folder_symcc(folder_fuzz_output+"/symcc"),
    folder_original_tc(folder_target_prog+"/testcases"),
    folder_debug(folder_target_prog+"/debug"),
    folder_crashes(folder_target_prog + "/fuzz_output/" + set.foldCrashes),
    folder_fuzzer_tc_master(folder_target_prog + "/fuzz_output" + set.kAFLTCMPathSuffix ),
    folder_fuzzer_tc_symcc(folder_target_prog + "/fuzz_output" + kAFLTCQPathSuffix ),
    folder_misc(folder_target_prog + "/misc"),
    folder_showmap_test(folder_misc + kFolderShowmapSuffix),
    time_last_showmap(std::chrono::system_clock::now()),
    time_last_symcc(std::chrono::system_clock::now()),
    time_last_no_crashes(std::chrono::system_clock::now())
{

    id = FuzzingContext::getIdFromFolder(folder_target_prog);

    // check on mode only for the first folder 
    // as this suffice and no need to check for all of them
    properAssert( !folderFileExists(getFolderMisc()) || 0 != mode_ow_cont, "Folder "+getFolderMisc()+" exists, yet mode=0. Set either overwrite( -ow ) or continue( -cont) mode. Alternatively, erase folders.");
    
    if( 2 != mode_ow_cont ){
 
        // misc
        if( folderFileExists(getFolderMisc()))
            fs::remove_all( fs::path{getFolderMisc()} );
        fs::create_directories( fs::path{getFolderMisc()} );

        // Prepare fuzzing folders
        if( folderFileExists(getFolderInput() )   )
            fs::remove_all( fs::path{getFolderInput()} );
        if( folderFileExists(getFolderOutput()) )
            fs::remove_all( fs::path{getFolderOutput()} );
        fs::create_directories( fs::path{getFolderInput()} );
        fs::create_directories( fs::path{getFolderOutput()} );

        // copy testcasess
        if( 0 == set.max_testacases )
            fs::copy( fs::path{getFolderOriginalTC()}, fs::path{getFolderInput()} );
        else{
            uint tot_copied = 0;
            uint i=0;
            while( i < 50 && tot_copied < set.max_testacases){
                std::string tc_file = getFolderOriginalTC() + "/" + std::to_string(i);
                if( folderFileExists( tc_file  ) && fs::file_size(tc_file) < set.max_file_size_mb * 1024 * 1024 ) {
                    fs::copy( fs::path{tc_file}, fs::path{getFolderInput()+"/"} );
                    tot_copied++;
                }
                i++;
            }
        }
        // create synthetic if no TC were copied
        if( 0 == countFilesInDirectory(getFolderInput()) ){
            std::ofstream file(getFolderInput()+"/synthetic", std::ios::binary);
            if ( file.is_open()) {
                for (int i = 0; i < 256; i++)
                    file.write((char*)&i, sizeof(i));
                file.close();
            }
        }


        // showmap_test
        if( folderFileExists(folder_showmap_test))
            fs::remove_all( fs::path{folder_showmap_test} );
        fs::create_directories( fs::path{folder_showmap_test} );

        // symcc folder 
        if( folderFileExists(folder_symcc))
            fs::remove_all( fs::path{folder_symcc} );
        fs::create_directory( fs::path{folder_symcc} );
        fs::create_directory( fs::path{folder_symcc+"/queue"} );
        fs::create_directory( fs::path{folder_symcc+"/temp"} );
        // debug
        if( folderFileExists(folder_debug))
            fs::remove_all( fs::path{folder_debug} );
        fs::create_directories( fs::path{folder_debug} );
    }


    allocateShared<Shared_memory,1>( &shm, shm_id );
    new(shm) Shared_memory();
    shm->id = atoi(id.c_str());

    // get file_binary path
    std::string filepath_fuzz_info {folder_target_prog + "/fuzz_info.txt"} ;
    std::ifstream f(filepath_fuzz_info);
    getline(f,file_binary_only);
    getline(f,param_binary);
    getline(f,afl_fold);
    getline(f,def_fold);
    getline(f,ld_lib);
    getline(f,cwd_lib);
    f.close();

    if( file_binary_only.find("defaultc") == std::string::npos ){
        std::cout   << KERR
                    << "Missing defaultc in folder : " << folder_target_prog << " " << file_binary_only << std::endl << KNRM;        
        shm->state = State::killed;
        //freeShm();
        return;
    }


    file_binary_afl         = file_binary_only;
    file_binary_afl.replace(file_binary_afl.find("defaultc"), std::string("defaultc").size(), afl_fold);
    file_binary_afl_true    = file_binary_only;
    file_binary_afl_true.replace(file_binary_afl_true.find("defaultc"), std::string("defaultc").size(), "lfa");
    file_binary_hongg       = file_binary_only;
    file_binary_hongg.replace(file_binary_hongg.find("defaultc"), std::string("defaultc").size(), "hongg");
    file_binary_cmp         = file_binary_only;
    file_binary_cmp.replace(file_binary_cmp.find("defaultc"), std::string("defaultc").size(), "aflcmp");
    file_binary_symcc       = file_binary_only;
    file_binary_symcc.replace(file_binary_symcc.find("defaultc"), std::string("defaultc").size(), "symcc");
    file_symcc_input        = folder_misc+"/symcc_input";
    file_sim_input          = folder_misc+"/sim_input";
    
    std::string symcc_base  = fs::path( file_binary_symcc ).filename();

    file_sim_output         = folder_misc+"/sim_output";
    file_serial             = folder_misc+"/serial";

    // check if AFL , symcc binaries are present 
    if( fs::exists(file_binary_afl) )  
        has_afl = true;
    if( fs::exists(file_binary_afl_true) )  
        has_afl_true = true;
    if( fs::exists(file_binary_hongg) )  
        has_hongg = true;
    if( fs::exists(file_binary_cmp) )  
        has_cmp = true;
    if( fs::exists(file_binary_symcc) )
        has_sym = true;
    only_gcc = !has_afl && !has_sym;
    

    if( ! fs::exists(file_binary_only) )  {
        std::cout   << KERR
                    << "Missing even gcc binaries " << folder_target_prog << std::endl << KNRM;        
        shm->state = State::killed;
        //freeShm();
        return;
    }

    // load previous state if cont
    if( 2 == mode_ow_cont ){
        std::cout<<KMAG <<"Deserialize" << KNRM << std::endl;
        deserialize();
        // if Honggfuzz then copy the found testcases
        if( Fuzzer::Honggfuzz == set.fuzzer ){
            copyFiles( folder_fuzz_output+"/honggfuzz", folder_fuzz_input );
        }
    }

    // each program gets its own copy of afl-showmap (and afl-qemu-trace).
    // this is due to some programs entirely remove the common AFLplusplus folder and 
    // thus preventing the whole fuzzer from producing correct coverage
    fs::copy( fs::path{kFolderAFLPPShowmap+"afl-showmap"}, fs::path{getFolderMisc()+"/afl-showmap"} );
    fs::copy( fs::path{kFolderAFLPPShowmap+"afl-qemu-trace"}, fs::path{getFolderMisc()+"/afl-qemu-trace"} );
    if (getEnvironmentVariable("BOIAN_HONGGFUZZ", false ) != ""){
        fs::copy( fs::path{kFolderHonggfuzz+"honggfuzz"}, fs::path{getFolderMisc()+"/honggfuzz"} );
        fs::copy( fs::path{kFileQemu}, fs::path{getFolderMisc()+"/qemu-x86_64"} );
    }


    if( Fuzzer::AFLPP == set.fuzzer ){
        // prepare vector of inputs for execv for AFL master
        afl_master_args.push_back("afl-fuzz");
        afl_master_args.push_back("-D");
        afl_master_args.push_back("-s");            // fix random seed
        afl_master_args.push_back("1");
        afl_master_args.push_back("-M");            // master
        afl_master_args.push_back("aflm");
        afl_master_args.push_back("-m");            // memory limit
        afl_master_args.push_back(set.afl_mem_limit);
        afl_master_args.push_back("-t");            // time limit
        afl_master_args.push_back("+"+std::to_string(int(set.max_time_afl * 1000)));
        afl_master_args.push_back("-i");
        afl_master_args.push_back(folder_fuzz_input);
        afl_master_args.push_back("-o");
        afl_master_args.push_back(folder_fuzz_output);
        if( has_cmp ){
            afl_master_args.push_back("-c");
            afl_master_args.push_back(file_binary_cmp);
        }
        if( !has_afl )
            afl_master_args.push_back(kBinModeSwitch);        // binary only mode    
        afl_master_args.push_back("--");
        afl_master_args.push_back( has_afl ? file_binary_afl : file_binary_only);
        if( param_binary.size() > 0 ){
            auto opar = param_binary;
            size_t pos = opar.find(" @@");
            if( pos != std::string::npos ){
                opar.replace(pos, std::string(" @@").length(), "");
                if( opar.size() > 0 )  
                    afl_master_args.push_back( opar );
                afl_master_args.push_back( "@@" ); 
            }
        }

    }
    else if( Fuzzer::AFL == set.fuzzer ){
        // prepare vector of inputs for execv for AFL master
        afl_master_args.push_back("afl-fuzz");
        afl_master_args.push_back("-M");            // master
        afl_master_args.push_back("aflm");
        afl_master_args.push_back("-m");            // memory limit
        afl_master_args.push_back(set.afl_mem_limit);
        afl_master_args.push_back("-t");            // time limit
        afl_master_args.push_back("+"+std::to_string(int(set.max_time_afl * 1000)));
        afl_master_args.push_back("-i");
        afl_master_args.push_back(folder_fuzz_input);
        afl_master_args.push_back("-o");
        afl_master_args.push_back(folder_fuzz_output);
        if( !has_afl )
            afl_master_args.push_back(kBinModeSwitch);        // binary only mode    
        afl_master_args.push_back("--");
        afl_master_args.push_back( has_afl_true ? file_binary_afl_true : file_binary_only);
        if( param_binary.size() > 0 ){
            auto opar = param_binary;
            size_t pos = opar.find(" @@");
            if( pos != std::string::npos ){
                opar.replace(pos, std::string(" @@").length(), "");
                if( opar.size() > 0 )  
                    afl_master_args.push_back( opar );
                afl_master_args.push_back( "@@" ); 
            }
        }
    }
    if( Fuzzer::Honggfuzz == set.fuzzer ){
        // prepare vector of inputs for execv for AFL master
        afl_master_args.push_back("honggfuzz");
        afl_master_args.push_back("-t");            // time limit
        afl_master_args.push_back("+"+std::to_string(set.max_time_afl));
        afl_master_args.push_back("-i");
        afl_master_args.push_back(folder_fuzz_input);
        afl_master_args.push_back("-o");
        afl_master_args.push_back(folder_fuzz_output+"/honggfuzz");
        afl_master_args.push_back("-W");    //write report / crash folder
        afl_master_args.push_back(folder_crashes);
        afl_master_args.push_back("-n");    // one core
        afl_master_args.push_back("1");

        // add '-s' for honggfuzz for stdin fuzzing
        if( param_binary.size() > 0 ){
            auto opar = param_binary;
            size_t pos = opar.find(" @@");
            if( pos == std::string::npos ){
                afl_master_args.push_back("-s");    // stdin input
            }
        }
        else
            afl_master_args.push_back("-s");

        afl_master_args.push_back("--");
        if( !has_afl )
            //afl_master_args.push_back(kFileQemu);        // binary only mode    
            afl_master_args.push_back(getFolderMisc()+"/qemu-x86_64");        // binary only mode    
        afl_master_args.push_back( has_hongg ? file_binary_hongg : file_binary_only);
        if( param_binary.size() > 0 ){
            auto opar = param_binary;
            size_t pos = opar.find(" @@");
            if( pos != std::string::npos ){
                opar.replace(pos, std::string(" @@").length(), "");
                if( opar.size() > 0 )  
                    afl_master_args.push_back( opar );
                afl_master_args.push_back( "___FILE___" ); 
            }
        }
    }

    // prepare vector of inputs for execv for SYMCC
    if( has_sym) { 
        symcc_args.push_back( symcc_base );
        if( param_binary.size() > 0 )
            symcc_args.push_back( param_binary );
        symcc_args.push_back(file_symcc_input);
    }

 
}

FuzzingContext::~FuzzingContext(){
    fuzzKill();
    freeShm();
}


std::string FuzzingContext::getFolderRoot() const { return folder_target_prog ;}
std::string FuzzingContext::getFolderInput() const { return folder_fuzz_input ;}
std::string FuzzingContext::getFolderOutput() const { return folder_fuzz_output ;}
std::string FuzzingContext::getFolderOriginalTC() const { return folder_original_tc ;}
std::string FuzzingContext::getFolderFuzzerTCMaster() const { return folder_fuzzer_tc_master ;}
std::string FuzzingContext::getFolderFuzzerTCSymcc() const { return folder_fuzzer_tc_symcc ;}
std::string FuzzingContext::getFolderMisc() const { return folder_misc; }
std::string FuzzingContext::getFuzzBinary() const { return file_binary_afl; }
std::vector<std::string> FuzzingContext::getArgs() const { return afl_master_args; }
State FuzzingContext::getState() const { return shm->state; }
Action FuzzingContext::getAction() const { return shm->action; }
pid_t FuzzingContext::getPid() const { return shm->afl_pid; }
MAB &FuzzingContext::getMab() { return mab; }
std::string FuzzingContext::get_folder_showmap_test() const { return folder_showmap_test;}
std::string FuzzingContext::get_folder_target_prog() const{ return folder_target_prog; }
std::string FuzzingContext::get_folder_symcc() const { return folder_symcc;}
std::string FuzzingContext::get_folder_misc() const { return folder_misc;}
std::string FuzzingContext::get_folder_debug() const { return folder_debug;}
std::string FuzzingContext::get_file_binary_only() const { return file_binary_only;}
std::string FuzzingContext::get_file_binary_afl() const { return file_binary_afl;}
std::string FuzzingContext::get_file_symcc_input() const { return file_symcc_input; }
std::string FuzzingContext::get_file_sim_input() const { return file_sim_input; }
std::string FuzzingContext::get_file_binary_symcc() const { return file_binary_symcc;}
std::string FuzzingContext::get_param_binary() const { return param_binary;}
std::string FuzzingContext::get_debug_afl_file() const { return folder_debug + "/afl_fuzz.out";}
std::string FuzzingContext::get_debug_showmap_file() const { return folder_debug + "/showmap_fuzz.out";}
std::string FuzzingContext::get_debug_sym_file() const { return folder_debug + "/sym_fuzz.out";}
std::string FuzzingContext::get_debug_sym_showmap_file() const { return folder_debug + "/ssshowmap_fuzz.out";}
std::string FuzzingContext::get_file_sim_output() const { return file_sim_output; }


double FuzzingContext::getCurScore() const { 

    // if ran too short, then return constant high score (so cannot be evicted)
    auto curr_time =  std::chrono::duration_cast<std::chrono::milliseconds>( 
                                        std::chrono::system_clock::now() - time_of_schedule ).count()/1000.0;
    if( curr_time < set.time_min_run_secs )
        return kLargeNumberForScore;

    // otherwise return the real score
    return mab.score();

}

double FuzzingContext::getCurFuzzTime() const { return timeElapsedMSecs(time_of_schedule)/1000.0; }



void FuzzingContext::setPid( pid_t val ){ shm->afl_pid = val; }
void FuzzingContext::setPidShowmap( pid_t val ){ shm->showmap_pid = val; }
void FuzzingContext::setPidSym( pid_t val ){ shm->sym_pid = val; }
void FuzzingContext::setAction ( Action act ){ shm->action = act;}

void FuzzingContext::set_time_of_start_symcc(){ shm->time_of_start_symcc = std::chrono::system_clock::now(); }
void FuzzingContext::set_time_of_pause_symcc(){ shm->time_of_pause_symcc = std::chrono::system_clock::now(); }
void FuzzingContext::set_time_of_stop_symcc(){  shm->time_of_stop_symcc = std::chrono::system_clock::now();  }
double FuzzingContext::get_symcc_running_time() { return timeElapsedMSecs( shm->time_of_start_symcc ); }
double FuzzingContext::get_symcc_pause_time() { return timeElapsedMSecs( shm->time_of_pause_symcc ); }
double FuzzingContext::get_symcc_start_stop_diff() {
    return std::chrono::duration_cast<std::chrono::milliseconds>( shm->time_of_start_symcc - shm->time_of_stop_symcc ).count()/1000.0;
}


bool FuzzingContext::fuzzInit(){
    shm->state          = State::running;
    time_of_schedule    = std::chrono::system_clock::now();
    if( Fuzzer::AFLPP == set.fuzzer || Fuzzer::AFL == set.fuzzer ){
        shm->add_score      = 0;
        shm->coverage       = 0;
    }
    return true;
}

bool FuzzingContext::fuzzCont(){  

    if( ! isProcessValid( shm->afl_pid)  ) {
        std::cout << KINFO "Process " << shm->afl_pid << " does not exist\n" << KNRM;
        shm->state = State::killed;
        fuzzKill();
        return false;
    }

    shm->state          = State::running;
    time_of_schedule    = std::chrono::system_clock::now();
    shm->add_score      = 0;
    shm->coverage       = 0;

    set_time_of_start_symcc();

    if( shm->action == Action::showmap && shm->showmap_pid > 0 ){
        if( ! isProcessValid( shm->showmap_pid)  ){
            shm->action = Action::fuzz; 
            std::cout<<"showmap process does not exist: " << shm->showmap_pid << std::endl;
            killpg( getpgid(shm->afl_pid), SIGCONT ) ;
        }
        else{
            std::cout<<"start with showmap\n"; 
            killpg( getpgid(shm->showmap_pid), SIGCONT ) ;
        }
    }
    else if( shm->action == Action::symcc && shm->sym_pid > 0 ){
        if( ! isProcessValid( shm->sym_pid ) ){
            shm->action = Action::fuzz; 
            std::cout<<"sym process does not exist:  " << shm->sym_pid << std::endl;
            killpg( getpgid(shm->sym_pid), SIGTERM /* SIGKILL */ ) ;
            killpg( getpgid(shm->afl_pid), SIGCONT ) ;
        }
        else{
            std::cout<<"start with sym\n"; 
            killpg( getpgid(shm->sym_pid), SIGCONT ) ;
        }
    }
    else //if( shm->action == Action::fuzz)
    {
        std::cout<<"start with afl " << shm->afl_pid << std::endl;    
        killpg( getpgid(shm->afl_pid), SIGCONT ) ;
    }

    return true;
}

void FuzzingContext::fuzzStop(){  

    killpg( getpgid(shm->afl_pid), SIGSTOP ) ;

    if( shm->showmap_pid > 0 ){
        killpg( getpgid(shm->showmap_pid), SIGSTOP ) ;
    }
    if( shm->sym_pid > 0 ){
        killpg( getpgid(shm->sym_pid), SIGSTOP ) ;
    }
    shm->state = State::stopped; 
    if( shm->action == Action::symcc)
        set_time_of_stop_symcc();

}

void FuzzingContext::fuzzKillStatic(Shared_memory *shm) {
    std::cout<<"fuzzkill:"<<shm->afl_pid<<"\n";
    //killpg (.. SIGKILL ); // bad because AFL++ does not handle this signal
    if( shm->afl_pid > 0 ){
        killpg( getpgid(shm->afl_pid), SIGTERM ) ;
    }
    if( shm->showmap_pid > 0 ){
        std::cout<<"kill showmap gpid" << shm->showmap_pid << std::endl;
        killpg( getpgid(shm->showmap_pid), SIGTERM ) ;
    }
    if( shm->sym_pid > 0 ){
        std::cout<<"kill sym gpid" << shm->sym_pid << std::endl;
        killpg( getpgid(shm->sym_pid), SIGTERM  ) ;
    }
}


void FuzzingContext::fuzzKill(){  
    fuzzKillStatic( shm );
}

void FuzzingContext::switchToFuzzingStatic(Shared_memory *shm) {

    if( shm->state == State::running ){
        if( killpg( getpgid(shm->afl_pid), SIGCONT )  == -1 )
            std::cout<<"Cannot start process "<< std::endl;
        else
            std::cout<<"Successfully started main thread "<< shm->afl_pid << std::endl;
    }
    shm->action = Action::fuzz;
}


void FuzzingContext::switchToFuzzing() {

    switchToFuzzingStatic( shm );
}

void FuzzingContext::freeShm(){
    
    if( shm_id > 0 &&  isMainThread() ){
        shmctl( shm_id, IPC_RMID, NULL );
    }
    shm_id = 0;

}


bool FuzzingContext::isGoodTC( const std::string &fpath ){
    if( fpath.find("queue/.state") != std::string::npos )  return false; // ignore AFL state file
    if( fpath.find("id") == std::string::npos 
    && fpath.find("honggfuzz") == std::string::npos ) return false;
    return true;
}


std::vector<std::string> FuzzingContext::getShowmapCandidates() {

    std::vector<std::string> showmap_candidates;
    if( ! fs::exists(getFolderFuzzerTCMaster()) ) return showmap_candidates;

    // if same timestamp, then return empty array
    fs::file_time_type ts = fs::last_write_time( fs::path{ getFolderFuzzerTCMaster() } );
    if( ts == last_write_showmap ) return showmap_candidates;
    last_write_showmap = ts;

    try{
        for( const auto &tc : fs::directory_iterator(getFolderFuzzerTCMaster()) ){
            std::string fpath = tc.path();
            if( ! isGoodTC( fpath ) ) continue;
            if( showmap_passed.find( fpath) != showmap_passed.end() ) continue;
            showmap_passed.insert( fpath );
            showmap_candidates.push_back( fpath );
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Error in : getShowmapCandidates " << e.what() << std::endl;
    }
    return showmap_candidates;
}


std::vector<std::string> FuzzingContext::getSymCandidates() {
    std::vector<std::string> sym_candidates;
    if( ! fs::exists(getFolderFuzzerTCMaster()) ) return sym_candidates;

    // if same timestamp, then return empty array
    fs::file_time_type ts = fs::last_write_time( fs::path{ getFolderFuzzerTCMaster() } );
    if( ts == last_write_sym ) return sym_candidates;
    last_write_sym = ts;

    try{
        for( const auto &tc : fs::directory_iterator(getFolderFuzzerTCMaster()) ){
            std::string fpath = tc.path(); 
            //if( fpath.find("id") == std::string::npos ) continue;
            if( ! isGoodTC( fpath ) ) continue;
            if( symcc_passed.find( fpath) != symcc_passed.end() ) continue;
            symcc_passed.insert( fpath );
            sym_candidates.push_back( fpath );
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Error in : getSymCandidates " << e.what() << std::endl;
    }
    return sym_candidates;
}


void FuzzingContext::printStats( std::string title){
    std::cout << "\r" << title << " " << getPid() <<"  " << file_binary_only 
                << "\n\tscore adds mult: " << mab.debug(0,0) 
                << "\n\tfolder root    : " << getFolderRoot() 
                << "\n" ; 
}



// thread safe way of updating add_score
void FuzzingContext::set_add_scoreStatic( Shared_memory *shmm, uint topup_score, uint topup_cover ) {
    shmm->add_score.fetch_add(topup_score);
    shmm->coverage.fetch_add(topup_cover);
}

// thread safe way of updating add_score
void FuzzingContext::set_add_score( uint topup_score, uint topup_cover  ) {
    FuzzingContext::set_add_scoreStatic( shm, topup_score, topup_cover);
}


// thread safe way of reading add_sc ore
uint FuzzingContext::get_add_scoreStatic(  Shared_memory *shmm  ) {
    return shmm->add_score.load();
}

// thread safe way of reading add_sc ore
uint FuzzingContext::get_add_score( ) {
    return get_add_scoreStatic( shm );
}

// thread safe way of reading add_sc ore
uint FuzzingContext::get_coverageStatic(  Shared_memory *shmm  ) {
    return shmm->coverage.load();
}

// thread safe way of reading add_sc ore
uint FuzzingContext::get_coverage( ) {
    return get_coverageStatic( shm );
}

void FuzzingContext::updateScoreState( double time_passed ){
    auto tmp_coverage   = shm->add_score.exchange(0);
    auto tmp_edges      = shm->coverage.exchange(0);
    mab.update( tmp_coverage, time_passed  );
    shm->tot_coverage   += tmp_coverage ;
    shm->tot_edges      += tmp_edges ;
    time_total_fuzz     += time_passed;
}



void FuzzingContext::serialize(){
    std::ofstream ofs(file_serial);
    boost::archive::text_oarchive oa(ofs);
    oa << time_total_fuzz;
    oa << num_tc;
    oa << showmap_passed;
    oa << symcc_passed;   
    oa << mab;
    oa << (*shm);
    oa << afl_setup_done;
    oa << no_bootstraps;
    oa << no_crashes;
}

void FuzzingContext::deserialize(){
    if( !folderFileExists(file_serial) ){ 
        std::cout<< KERR << "Cannot find serialization file " << file_serial <<  KNRM << "\n";
        return;
    }
    std::ifstream ifs(file_serial);
    boost::archive::text_iarchive ia(ifs);
    ia >> time_total_fuzz;
    ia >> num_tc;
    ia >> showmap_passed;
    ia >> symcc_passed;   
    ia >> mab;
    ia >> (*shm);
    ia >> afl_setup_done;
    ia >> no_bootstraps;
    ia >> no_crashes;

    std::cout<<"deser mab : " << mab.debug(0,0) << "\n";
}


