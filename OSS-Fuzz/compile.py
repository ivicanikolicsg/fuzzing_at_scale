import multiprocessing, os, subprocess, glob, shutil, sys, psutil, yaml
import yaml, glob, os, subprocess
import multiprocessing
from multiprocessing import Manager
from fuzz_config import *



filepath_afl_cc     = folder_afl   + '/afl-clang-fast'
filepath_afl_cxx    = folder_afl   + '/afl-clang-fast++'
filepath_aflpp_cc   = folder_aflpp + '/afl-clang-fast'
filepath_aflpp_cxx  = folder_aflpp + '/afl-clang-fast++'

filepath_afl_driver = folder_afl   + '/afl_driver/libAFL.a'
filepath_aflpp_driver = folder_aflpp   + '/libAFLDriver.a'
filepath_our_driver = folder_main + '/fuzzing_drivers/our_driver/StandaloneFuzzTargetMain.o'

for f in [filepath_afl_cc, filepath_afl_cxx, filepath_aflpp_cc, filepath_aflpp_cxx, 
          filepath_afl_driver, filepath_aflpp_driver, filepath_our_driver]:
    if not os.path.exists(f):
        print(FAIL + f"{f} does not exist" + ENDC)
        exit(1)

AFL = ("lfa", filepath_afl_cc, filepath_afl_cxx, 
    '-Wl,--allow-multiple-definition', 
    '-Wl,--allow-multiple-definition', 
    {},
    filepath_afl_driver, 
    ) 

AFLPP = ("aflpp", filepath_aflpp_cc, filepath_aflpp_cxx, 
    "", 
    "", 
    {},
    filepath_aflpp_driver
    )

DEFAULT = ("defaultc", "clang", "clang++",
    "", 
    "",
    {},
    filepath_our_driver
    )


compilers = []
compilers.append( AFL )
compilers.append( AFLPP )
compilers.append( DEFAULT )

def compile_one(d, counter, total):
    counter.value += 1
    print(f'Compiling {d} :  {counter.value} / {total}', flush=True)

    dockerfile =  d + '/Dockerfile'
    if not os.path.isfile(dockerfile):
        print('No Dockerfile found in', d)
        return
    build_file = d + '/build.sh'
    if not os.path.isfile(build_file):
        print('No build.sh found in', d)
        return
    
    project_name = os.path.basename(d)

    current_dir = os.getcwd()

    for compiler,CC,CXX,CFLAGS,CXXFLAGS,env_dict,lib_fuzz_eng in compilers:

        env = os.environ.copy()
        env['CC']=CC
        env['CXX']=CXX
        env['CFLAGS']=CFLAGS
        env['CXXFLAGS']=CXXFLAGS
        env['SYMCC_NO_SYMBOLIC_INPUT']='1'
        env['LD']=CC
        env['LDFLAGS'] = '-fsanitize=address'
        env['LIB_FUZZING_ENGINE'] = lib_fuzz_eng


        # create a new directory for the compiler
        dst     = folder_oss_compiled + '/' + project_name + "_" + compiler
        if not os.path.isdir(dst):
            os.mkdir(dst)

        # create OUT folder
        out_dir = dst + '/OUT'
        if not os.path.isdir(out_dir):
            os.mkdir(out_dir)
        env['OUT'] = out_dir

        print('DESTINATION: ', dst)

        # copy everything to the new directory
        os.system('cp  ' + d + '/* ' + dst + '/')

        os.chdir(dst)

            
        # read dockerfile and execute commands locally
        SRC = dst
        WORKDIR = None
        with open(dockerfile, 'r') as stream:
            lines = stream.readlines()
            for line in lines:
                if line.startswith('RUN '):
                    cmd = line[4:].strip().replace('$SRC', SRC)
                    print('Executing', cmd)
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if process.returncode != 0:
                        print(f'Error: {stderr.decode()}')
                    else:
                        print(stdout.decode())
                elif line.startswith('COPY ') and '$SRC' in line and SRC is not None:
                    cmd = line[5:].strip()
                    cmd = cmd.replace('$SRC', SRC)
                    print('Copying files', cmd)
                    os.system( 'cp ' + cmd  )
                elif line.startswith('WORKDIR '):
                    WORKDIR = line[8:].strip().replace('$SRC', SRC)
                    print('Setting WORKDIR to', WORKDIR)
        

        if WORKDIR is not None:
            os.chdir( WORKDIR )

        env['SRC'] = SRC

        # create WORK folder (temp folder to store intermediate files)
        work_dir = dst + '/WORK'
        if not os.path.isdir(work_dir):
            os.mkdir(work_dir)
        env['WORK'] = work_dir

        # execute build.sh
        print('Executing build.sh')
        build_path = dst + '/build.sh'
        # set executable flag
        os.system('chmod +x ' + build_path)
        
        process = subprocess.Popen( build_path, shell=True, env=env)
        process.wait()
        if process.returncode != 0:
            print(f'Error: {stderr.decode()}')
        else:
            print(stdout.decode())

if __name__ == '__main__':


    tot_found = 0
    targets = []
    for d in glob.glob(folder_oss_projects + '*'):
        if os.path.isdir(d):
            if os.path.isfile(d + '/project.yaml'):
                with open(d + '/project.yaml', 'r') as stream:
                    data = yaml.safe_load(stream)
                    if not ('language' in data and data['language'][:1] == 'c' \
                        and 'fuzzing_engines' in data \
                        and 'afl' in data['fuzzing_engines']): 
                            continue
                    
                    targets.append( d )

                    tot_found += 1
                    print('Found: ' + d)
                    print(data['language'])
                    print(data['fuzzing_engines'])
                    

    print('Targets:', len(targets))

    if not os.path.exists(folder_oss_compiled):
        os.mkdir(folder_oss_compiled)


    counter = Manager().Value('i', 0)
    pool = multiprocessing.Pool(no_cpu)
    _res = pool.starmap(compile_one, ( (t,counter,len(targets)) for t in targets ) )
    pool.close()
    pool.join()
