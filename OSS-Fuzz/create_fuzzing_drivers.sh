#!/bin/bash

if [ -z "${BOIAN_AFL}" ]; then
  echo "Error: The environment variable BOIAN_AFL is not set."
  exit 1
fi

if [ -z "${BOIAN_AFLPP}" ]; then
  echo "Error: The environment variable BOIAN_AFLPP is not set."
  exit 1
fi

current_folder=$(pwd)


# Driver for AFL
mkdir -p ${current_folder}/fuzzing_drivers/afl_driver
cd ${current_folder}/fuzzing_drivers/afl_driver
mkdir -p ${BOIAN_AFL}/afl_driver
wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/afl/afl_driver.cpp -O ./afl_driver.cpp && \
clang -Wno-pointer-sign -c ${BOIAN_AFL}/llvm_mode/afl-llvm-rt.o.c -I./afl && \
clang++ -std=c++11 -O2 -c ./afl_driver.cpp && \
ar r ./libAFL.a *.o
cp ./libAFL.a ${BOIAN_AFL}/afl_driver/libAFL.a


# Driver for AFL++
cd ${BOIAN_AFLPP}/utils/aflpp_driver
make


# Driver for gcc
cd ${current_folder}
mkdir -p fuzzing_drivers/our_driver
cd fuzzing_drivers/our_driver
wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c
clang -O2 -fPIE -c ./StandaloneFuzzTargetMain.c -o StandaloneFuzzTargetMain.o

