# Fuzzing at scale project
This is the code for the paper "Fuzzing at Scale: The Untold Story of the Scheduler".

The projects consists of a few parts: 
* Prepare UbuntuBench
* Prepare OSS-Fuzz benchmark
* Run the schedulers

Make sure you have installed AFL and AFL++ and export environ vars `BOIAN_AFL,BOIAN_AFLPP` to point to the absolute paths of their corresponding folders, i.e. 
```
export BOIAN_AFL=/mnt/home/.../AFL/
export BOIAN_AFLPP=/mnt/home/.../AFLPlusPlus/
```

## Download and compilation of UbuntuBench
Download (folder `./UbuntuBench/download_packages`) consists of a single step/script `cd download_packages; python down.py`. This takes a lot of space (several hundreds of GB). The packages will be stored in `./packs`.

Compilation and preparation of UbuntuBench (folder `./UbuntuBench/compile_packages`) consists of three separate steps/scripts:
* `resolve_dependencies.py`  tries to install dependencies for the packages
* `compile.py`               tries to compile as many packages as possible 
* `get_interesting.py`       identifies produced binaries and tries to get all of their interesting parameters 

As a result, a new folder `fuzz_targets` will be automatically created and will contain all the necessary info about the fuzzing targets that schedulers use to fuzz at scale the binaries.

## Download and compilation of OSS-Fuzz packages
In `OSS-Fuzz` folder first download the packages with `git clone https://github.com/google/oss-fuzz`. 

Some of the OSS-Fuzz targets are libraries (not programs), so they need a special fuzzing driver to run. Install these drivers for AFL++, AFL, and `gcc` by running `create_fuzzing_drivers.sh`.

Then, similarly to UbuntuBench, run: `compile.py` to compile all,  `get_interesting.py` to create fuzz targets.

## Schedulers
In the `Schedulers` folder, first `make` the schedulers executable. 
Then export the environ variables to define what scheduler to use and on which targets:
```
export BOIAN_SCHEDULER=boian   # type of scheduler, can be "baseline", "mab", "discounted", or "boian"
export BOIAN_USE_CPUS=30            # number of CPU to use during fuzzing
export BOIAN_MINUTES_PER_TARGET=15  # average minutes per target
export BOIAN_FUZZ_TARGETS=/mnt/.../Fuzzing_at_scale_artifacts/OSS-Fuzz/fuzz_targets/ # path to the folder fuzz_targets either for UbuntuBench or OSS-Fuzz
```
Finally, run the selected scheduler `cd run; ./schedule`.

## Docker container
The project contains `Dockerfile` that creates image containing AFL/AFL++ fuzzers, OSS-Fuzz projects, and schedulers as described in the above steps. Note, it does not support UbuntuBench as compilation of these packages is opportunistic and requires multiple re-runs (abort and restart) thus it cannot be created from Dockerfile (needs to finish in a single run).

