import multiprocessing, os, subprocess, glob, shutil, sys, psutil
sys.path.append("../")
from fuzz_config import *


filepath_afl_cc     = folder_afl   + '/afl-clang-fast'
filepath_afl_cxx    = folder_afl   + '/afl-clang-fast++'
filepath_aflpp_cc   = folder_aflpp + '/afl-clang-fast'
filepath_aflpp_cxx  = folder_aflpp + '/afl-clang-fast++'

for f in [filepath_afl_cc, filepath_afl_cxx, filepath_aflpp_cc, filepath_aflpp_cxx]:
    if not os.path.exists(f):
        print(FAIL + f"{f} does not exist" + ENDC)
        exit(1)


if not os.path.exists(folder_ubuntu_packs):
    print('No pack folder here :', folder_ubuntu_packs)
    exit()

if not os.path.exists(folder_ubuntu_compiled):
    os.mkdir(folder_ubuntu_compiled)


# gcc with debian/rules
DEFAULT = ("defaultc", "gcc",  "g++",  "", "",{})

# AFL with debian/rules
AFL = ("lfa",filepath_afl_cc, filepath_afl_cxx, "", "", {}) 

# AFL++ with debian/rules
AFLPP = ("aflpp", filepath_aflpp_cc, filepath_aflpp_cxx, "", "", {})

# AFL++ but by calling explicitly ./configure, make, etc.
AFLQQ = ("aflqq",filepath_aflpp_cc, filepath_aflpp_cxx, "", "", {})

# Honggfuzz with debian/rules
HONGG = ("hongg", "XXX/hfuzz_cc/hfuzz-clang", "XXX/hfuzz_cc/hfuzz-clang++", "", "", {})

compilers = []
compilers.append( DEFAULT )
compilers.append( AFL )
#compilers.append( HONGG )
compilers.append( AFLPP )
compilers.append( AFLQQ )


def afl_compile_old(dst, env, compiler,CC,CXX,CFLAGS,CXXFLAGS ):

    # create tmp dir
    TMP_DIR = dst + '/tmp_dir_for_configure'
    TMP_DIR = os.path.abspath(TMP_DIR)
    if not os.path.exists(TMP_DIR):
        os.mkdir( TMP_DIR )


    print('')
    print(dst)
    run_conf = False
    run_make = False
    make_file= None
    run_cmake= False
    if os.path.exists(dst + '/CMakeLists.txt'):
        print('Cmake', dst)
        run_cmake = True
    elif os.path.exists(dst + '/aclocal.m4'):
        print('aclocal', dst)
        run_conf = True
        p = subprocess.Popen( 'cd ' + dst + ' ; autoreconf -fi ' , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
        p = subprocess.Popen( 'cd ' + dst + ' ; ./autogen.sh' , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
    elif os.path.exists(dst + '/autogen.sh'):
        print('autogen', dst )
        run_conf = True
        p = subprocess.Popen( 'cd ' + dst + ' ; ./autogen.sh' , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
    elif os.path.exists(dst + '/configure'):
        print('configure', dst)
        run_conf = True
    elif os.path.exists(dst + '/configure.ac'):
        print('configure.ac')
        run_conf = True
        p = subprocess.Popen( 'cd ' + dst + ' ; aclocal ; autoreconf -fi ' , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
    elif os.path.exists(dst + '/Makefile') or os.path.exists(dst + '/makefile') or os.path.exists(dst + '/GNUmakefile'):
        print('makefile')
        run_make = True
    elif os.path.exists(dst + '/Makefile.linux') or os.path.exists(dst + '/makefile.linux') or os.path.exists(dst + '/GNUmakefile'):
        print('makefile linux')
        run_make = True
        make_file = 'Makefile.linux' if os.path.exists(dst + '/Makefile.linux') else 'makefile.linux'
    elif os.path.exists(dst + '/build.sh'):
        print('build.sh', dst)
        p = subprocess.Popen( 'cd ' + dst + ' ; ./build.sh' , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
    elif os.path.exists(dst + '/setup.py'):
        print('Python', dst)
        p = subprocess.Popen( 'cd ' + dst + ' ; python setup.py install --prefix '+TMP_DIR , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()
    else:
        print('Unknown', dst)
        p = subprocess.Popen( 'ls '+dst , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()

    if run_conf:
        print('run conf')
        run_make = True
        q = 'cd ' + dst + ' ; ' +CONFIGURE_CALL+' --prefix "'+TMP_DIR+'"'
        p = subprocess.Popen( q , shell=True, executable='/bin/bash' , env=env )
        stdout, stderr = p.communicate()

    if run_make:
        special_file = '' if make_file is None else ' -f ' + make_file
        q = 'cd ' + dst + ' ; make -j 1 ' + special_file + ' '
        q += ' CC='+CC+' CXX='+CXX+' CFLAGS='+CFLAGS +' CXXFLAGS='+CXXFLAGS + ' LD='+CC + ' CCLD='+CC 
        print(q)
        p = subprocess.Popen( q , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()

    if run_cmake:
        special_file = '' if make_file is None else ' -f ' + make_file
        print('run cmake')
        CMAKE_CALL=make_cmake_call(CC,CXX,CFLAGS,CXXFLAGS)
        q = 'cd ' + TMP_DIR+' ; '+CMAKE_CALL+' -DCMAKE_INSTALL_PREFIX='+TMP_DIR
        q+= ' ; make -j 1 ' + special_file + ' '
        q+= ' CC='+CC+' CXX='+CXX+' CFLAGS='+CFLAGS +' CXXFLAGS='+CXXFLAGS + ' LD='+CC
        print(q)
        p = subprocess.Popen( q , shell=True, executable='/bin/bash', env=env )
        stdout, stderr = p.communicate()



def compile_one(src, cur):

    cur.value = cur.value+1
    print('\n Candidate : ', cur.value, tot, src, flush=True)

    dbase   = os.path.basename(src)
    FAKE_EVN_KEY_TO_DETECT_OUR_PROCS = 'FUZZR_PROC-'+src

    fpath_bad = folder_ubuntu_compiled + dbase + "_defaultc"+ '/bad_compile'
    if os.path.exists(fpath_bad): 
        print('Bad compile')
        return 

    for compiler,CC,CXX,CFLAGS,CXXFLAGS,env_dict in compilers:

        dst     = folder_ubuntu_compiled + dbase + "_"+compiler

        env = os.environ.copy()
        env[FAKE_EVN_KEY_TO_DETECT_OUR_PROCS] = '1'
        env['CC']=CC
        env['CXX']=CXX
        env['CFLAGS']=CFLAGS
        env['CXXFLAGS']=CXXFLAGS
        env['LD']=CC
        
        env['LDFLAGS'] = '-fsanitize=address'

        env.update( env_dict )

        print('copy', src, dst)


        fpath_done = dst + '/done_compile'
        if os.path.exists(fpath_done): 
            print('Done compile')
            continue # already processed

        # copy fresh folder
        if os.path.exists(dst):
            print('Exists', dst)
            continue
        shutil.copytree( src, dst, symlinks=True )

        try:
            if 'aflqq' not in compiler and 'defaultq' not in compiler:
                p = subprocess.Popen( 'cd ' + dst + '; ./debian/rules build' , shell=True, executable='/bin/bash', env=env )
                stdout, stderr = p.communicate()
                
                # if main (defaultc)  compilation failed, do not proceed further, 
                if 'defaultc' in compiler:
                    _ret = p.returncode
                    if _ret != 0: 
                        print(FAIL,'Compilation with ',compiler,' failed for ', src, ENDC )
                        with open(fpath_bad,'w') as f:
                            pass
                        break
            else:
                afl_compile_old(dst, env, compiler,CC,CXX,CFLAGS,CXXFLAGS)
        
        except:
            pass


        # remove all processes
        for p in psutil.process_iter(['pid', 'name', 'environ']):
            if  p.info['environ'] is not None and \
                FAKE_EVN_KEY_TO_DETECT_OUR_PROCS in p.info['environ']:
                    process = psutil.Process(p.info['pid'])
                    process.kill()
                    print('Kill leftover process')

        
        with open(fpath_done,'w') as f:
            pass


manager = multiprocessing.Manager()
cr = manager.Value('i',0)
alldirs = []
for f in glob.glob(folder_ubuntu_packs + '/*'):
    if os.path.isdir(f):
        alldirs.append( (f, cr) )

tot = len(alldirs)
print('Got packages ', tot )


pool = multiprocessing.Pool(no_cpu)
pool.starmap_async(compile_one, alldirs, chunksize=1)
pool.close()
pool.join()

