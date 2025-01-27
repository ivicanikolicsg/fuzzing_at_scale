#ifndef MAB_H
#define MAB_H

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "params.h"

class MAB{  

public:

    void update( double new_coverage, double used_time );
    std::string debug( double , double  );
    void updateSelectCount();

    double score() const;
    void adjustToNewGamma();

private:

    uint updates{1};
    uint selected{0};

    // new cov
    std::vector<double> buckets_cov{kInitialCoverage};
    double last_bucket_time{kInitialTime};
    double tot_cov{kInitialCoverage};
    double tot_time{kInitialTime};
    double cur_cov{kInitialCoverage};
    double cur_time{kInitialTime};


    void addToOneBucket( double new_coverage, double new_time );

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, [[maybe_unused]] const unsigned int version)
    {
        ar & updates;
        ar & selected;
        ar & buckets_cov;
        ar & last_bucket_time;
        ar & tot_cov;
        ar & tot_time;
        ar & cur_cov;
        ar & cur_time;
    }

};


void changeEpsilon( bool increase) ;
void changeIncrementEpsilon( double nv );
double getEpsilon();

int mabSample( std::vector<MAB *> &mabs );

void setGamma(double vg);

#endif