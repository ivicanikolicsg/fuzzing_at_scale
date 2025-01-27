#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "misc.h"
#include "add_structs.h"




void runAFL(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib );

void runAFLPlusPlus(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib );

void runHonggfuzz(std::vector<std::string> &aflpar,
                    Shared_memory *shm,
                    std::string &folder_target_prog, 
                    const int slave_id ,
                    std::string &ld_lib,
                    std::string &cwd_lib );

void checkShowmap( 
        std::vector<std::string> &showmap_cands,
        Shared_memory *shm,
        std::string folder_target_prog,
        std::string file_binary_afl,
        std::string file_binary_only,
        std::string param_binary,
        std::string ld_lib,
        std::string cwd_lib,
        int has_afl
    );

void checkSym( 
        std::vector<std::string> &sym_cands, 
        Shared_memory *shm,
        std::string folder_target_prog,
        std::string file_binary_afl,
        std::string file_binary_only,
        std::string file_binary_symcc,
        std::string param_binary,
        std::string ld_lib,
        std::string cwd_lib,
        int has_afl
    );



#endif