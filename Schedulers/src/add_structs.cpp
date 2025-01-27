#include "add_structs.h"

std::string getStateString( State s){ 
    if( s==State::init ) return "init";
    else if( s == State::running) return "run ";
    else if( s == State::stopped) return "stop";
    else return "kill";
}

std::string getActionString( Action s){ 
    if( s==Action::fuzz ) return "afl";
    else if( s == Action::showmap) return "show";
    else if( s == Action::out) return "out";
    else return "symc";
}
