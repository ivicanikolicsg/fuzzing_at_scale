#include <iostream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <sstream>

#include "mab.h"
#include "misc.h"
#include "system-stuff.h"

static std::mt19937 mt = std::mt19937(time(nullptr));

static double vgamma = kDynamicStartGamma;

void MAB::updateSelectCount(){ selected ++; }

static double min_epsilon = 0.01;
static double max_epsilon = 0.75; 
static double inc_epsilon = 0.05; 
static double cur_epsilon = 0.01; 


void changeIncrementEpsilon( double periods ) {
    inc_epsilon = (max_epsilon - min_epsilon) / periods;
}

void changeEpsilon( bool increase) { 
    cur_epsilon += (2*increase - 1) * inc_epsilon;
    cur_epsilon = std::max( cur_epsilon, min_epsilon);
    cur_epsilon = std::min( cur_epsilon, max_epsilon);
}
    
double getEpsilon() { return cur_epsilon; }

// sample according to softmax
int mabSample( std::vector<MAB*> &mabs) {

    static std::ofstream log_mab("lmab.log",std::ios::out);

    // use fast epsilon-greedy
    bool output_to_log = false;
    static auto time_prev_output = std::chrono::system_clock::now();
    if( set.secs_between_log_outputs > 0 && timeElapsedMSecs( time_prev_output ) > 1000 * set.secs_between_log_outputs ){
        time_prev_output    = std::chrono::system_clock::now();
        output_to_log       = true;
    }
    if( output_to_log){
        log_mab  << "\nRound : " << std::endl;
    }

    double max_score = -1;
    int max_index = -1;
    for( uint i=0; i< mabs.size(); i++){
        double score = mabs[i]->score();
        if( output_to_log ) {
            log_mab  
                << "choice: " << std::setw(3)<< i 
                << " : " << mabs[i]->debug(0,0) 
                << "  ::  " << std::setprecision(6)<<score << std::endl;
        }
        if( max_index <  0 || score > max_score ){
            max_index = i;
            max_score = score;
        }
    }
    std::uniform_real_distribution<float> d01(0,1);
    if(  d01(mt) < cur_epsilon ) {
        max_index = mt() % mabs.size();
        max_index = 0;
    }

    if( output_to_log){
        log_mab  <<"select : " << max_index << std::endl;
    }

    mabs[max_index]->updateSelectCount();
    return max_index ;

}


void MAB::addToOneBucket( double new_coverage, double new_time ){
    if( last_bucket_time + new_time <= kBucketsSecsLength ){
        cur_cov += new_coverage;
        cur_time+= new_time;
        buckets_cov[ buckets_cov.size() - 1] += new_coverage;
        last_bucket_time += new_time;
    }
    else{
        double cur_bucket_cov   = new_coverage * (kBucketsSecsLength - last_bucket_time ) / new_time;
        double left_coverage    = new_coverage - cur_bucket_cov;
        double left_time        = new_time - (kBucketsSecsLength - last_bucket_time);
        buckets_cov[ buckets_cov.size() - 1] += cur_bucket_cov;
        cur_cov += cur_bucket_cov;
        cur_time+= kBucketsSecsLength - last_bucket_time;

        cur_cov *= vgamma;
        cur_time*= vgamma;
        
        last_bucket_time = 0;
        buckets_cov.push_back(0.0);
        addToOneBucket( left_coverage, left_time );
    }
}

void MAB::update( double new_coverage, double new_time ){

    updates     += 1;
    tot_cov     += new_coverage;
    tot_time    += new_time;

    if( ! set.use_dynamic ) return;

    addToOneBucket( new_coverage, new_time);
    properAssert( cur_cov >= -0.01 , "negative coverage");
}


void setGamma(double vg) { vgamma = vg; }


void MAB::adjustToNewGamma(){

    double g = 1.0;
    cur_cov = 0;
    cur_time = 0;
    for( int i= buckets_cov.size()-1; i>=0; i-- ){
        cur_cov += g * buckets_cov[i];
        cur_time+= g * (uint(i) == buckets_cov.size()-1 ? last_bucket_time : kBucketsSecsLength) ;
        g *= vgamma;
    }
}


double MAB::score() const {

    return  tot_time < kMinSecsRun ? 
                kLargeNumberForScore : 
                ( set.use_dynamic ? cur_cov / cur_time : tot_cov / tot_time
                )    
        ;

}



std::string MAB::debug( double add_cov, double add_tim ){
    std::stringstream s;
    s   << std::fixed
        << std::setw(5) <<  buckets_cov.size() 
        << " " << std::setw(7) << std::setprecision(2) << cur_cov 
        << "   " 

        << std::setw(3)  << selected
        << " " << std::setw(5) << std::setprecision(0) << std::fixed << (cur_cov + add_cov )
        << "(" << std::setw(5) << std::setprecision(0) << (tot_cov+add_cov) << ")"
        << " " << std::setw(5) << std::setprecision(5) << std::fixed << vgamma
        << "(" << std::setw(5) << std::setprecision(0) << (cur_time + add_tim) 
        << " " << std::setw(5) << std::setprecision(0) << (tot_time + add_tim)  << ")"
        << " " << std::setw(10) << std::setprecision(6) << score() 
        ;//<< std::endl;
    return s.str();
}

