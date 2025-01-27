#ifndef FORK_SERVERS
#define FORK_SERVERS

#include <vector>   
#include "scheduler.h"
#include "system-stuff.h"

void startForkserver(int parent_pipe[2], int child_pipe[2] );

void writeString( int parent_pipe[2], std::string s);
void writeVectorStrings( int parent_pipe[2], const std::vector<std::string> &v );

template <class T>
T readPOD( int parent_pipe[2]) {
    T v;
    properAssert(  read(parent_pipe[0], &v, sizeof(v)) != -1, "read from parent POD");
    return v;
}


template <class T>
void writePOD( int parent_pipe[2], T v) {

    auto rb = write(parent_pipe[1], &v,  sizeof(v) );
    if (sizeof(T) != rb ){
        std::cout<<"wr differ " << rb << " " << sizeof(T) << std::endl;
        properAssert( 0, "kr");
    }
}

std::string readString( int parent_pipe[2]);



#endif
