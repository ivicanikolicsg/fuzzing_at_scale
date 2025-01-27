#ifndef ADD_STRUCTS_H
#define ADD_STRUCTS_H

#include <atomic>
#include <cstring>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/nvp.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/split_member.hpp>
#include <boost/serialization/split_free.hpp>

#include "params.h"

enum class State{ init = 0, running = 1, stopped = 2, killed = 3 };
enum class Action{ fuzz = 0, showmap, symcc, out };

std::string getStateString( State s);
std::string getActionString( Action s);


// to serialize atomic uint
namespace boost::serialization {

template<class Archive>
void save(Archive & ar, const std::atomic<uint> &t, [[maybe_unused]] unsigned int version) {
    uint x = t.load();
    ar & boost::serialization::make_nvp("atomic", x);
}

template<class Archive>
void load(Archive & ar, std::atomic<uint> &t, [[maybe_unused]]unsigned int version) {
    uint x;
    ar & boost::serialization::make_nvp("atomic", x);
    t.store(x);
}

template<class Archive>
inline void serialize(Archive & ar, std::atomic<uint> &t, [[maybe_unused]]unsigned int file_version) {
    boost::serialization::split_free(ar, t, file_version);
}
} 






struct Shared_memory{
    Shared_memory(){
        memset(show, 0, 1<<16 );
        add_score.store(0);
        coverage.store(0);
    }

    uint id{0};

    char show[1<<16];
    std::atomic<uint> add_score{0};
    std::atomic<uint> coverage{0};

    uint tot_coverage{0};
    uint tot_edges{0};

    uint showmap_session{0};
    State state{State::init};
    Action action{Action::fuzz};
    bool paused_symcc{false};
    uint symcc_id{0};
    uint to_process_show{0}, cur_process_show{0};
    uint to_process_sym{0}, cur_process_sym{0};
    pid_t afl_pid{-1}, showmap_pid{-1}, sym_pid{-1};

    // 1) to make sure symcc does not run beyond g_max_time_consecutive_symcc
    // 2) to extend timers 
    std::chrono::time_point<std::chrono::system_clock> time_of_start_symcc, time_of_pause_symcc, time_of_stop_symcc; 

    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, [[maybe_unused]] const unsigned int version)
    {
        ar & id;
        ar & show;
        ar & BOOST_SERIALIZATION_NVP(add_score);
        ar & BOOST_SERIALIZATION_NVP(coverage);
        ar & tot_coverage;
        ar & tot_edges;
        ar & showmap_session;
        ar & symcc_id;
        ar & to_process_show;
        ar & cur_process_show;
        ar & to_process_sym;
        ar & cur_process_sym;
    }
    
};


struct Debug{
    // times for profiling
    double debug_time_tot{0}, debug_time_fix_proc{0}, debug_time_readafl{0};
    double debug_time_stepfuzz{0}, debug_time_multicore{0}, debug_time_debug_time_evsch{0};
};

#endif