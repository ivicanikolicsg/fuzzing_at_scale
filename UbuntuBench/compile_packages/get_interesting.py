import multiprocessing, os, subprocess, glob, shutil, sys, psutil, re, math, numpy, hashlib, sys, psutil, getpass, time
from subprocess import Popen, PIPE, STDOUT
sys.path.append("../")
from fuzz_config import *
import signal
from timeout_decorator import timeout, TimeoutError


filepath_afl_showmap	= folder_aflpp + '/afl-showmap'
max_tc_size	= 1024 * 1024


def hashfile(fpath):

    BUF_SIZE = 65536  
    md5 = hashlib.md5()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()

def str_to_int(x):
    try:
        int(x)
    except:
        return 0
    return int(x)



EXEFLAG_NONE        = 0x0000
EXEFLAG_LINUX       = 0x0001
EXEFLAG_32BITS      = 0x0010
EXEFLAG_64BITS      = 0x0020
_EXE_SIGNATURES = [
    (b'\x7fELF\x01', EXEFLAG_LINUX | EXEFLAG_32BITS),
    (b'\x7fELF\x02', EXEFLAG_LINUX | EXEFLAG_64BITS)
]

def is_elf(filepath):
    try:
        with open(filepath, "rb") as f:
            buf = ""
            buf_len = 0
            for sig, flags in _EXE_SIGNATURES:
                sig_len = len(sig)
                if buf_len < sig_len:
                    buf = f.read(sig_len - buf_len)
                    buf_len = sig_len
                if buf == sig:
                    return flags
    except:
        pass

    return EXEFLAG_NONE




def rem_comma_pipes(s):
    ma = re.search("[,\|]",s)
    if ma:
        s = s[:ma.span()[0]]
    return s

def list_files(dir, pred_good, trans_name ):
    res = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            f = os.path.join(root, file)
            if pred_good(f):
                res.append( trans_name( f ) )
    return res


def timeout_handler(signum, frame):
    raise TimeoutError('fuzz_timeout')

def is_fuzz_timeout(e):
    en = str(e)[1:-1]
    return en == 'fuzz_timeout'

def get_cov(fold,f, tc_candidates, probs, afl_binary, conf_has_afl, cwd_lib, param, env, timout ):

    sm = folder_temp_showmaps + '/' + fold
    if not os.path.exists(sm):
        os.mkdir(sm)
        ch = numpy.random.choice(tc_candidates, config_no_tc, p=probs )
        tcno = 0
        for one_tc in ch:
            if tcno > 2: break
            shutil.copyfile(one_tc,sm+'/'+str(tcno))
            tcno +=1
    
    showmap_file = folder_temp_showmaps + '/' + fold + '-showmap.txt'

    tot_bits = 0
    c = ('cd '+cwd_lib + '; ' if cwd_lib is not None else '') +' pwd; ' + filepath_afl_showmap 
    c+= '' if conf_has_afl is not None else ' -Q ' 
    c+=' -t ' + str(int(1000*timout)) + ' -i '+sm+' -o '+showmap_file+' -C -- ' + (f if not conf_has_afl is not None else afl_binary) +' ' +  param + ' @@'
    if True:
        if conf_has_afl is None:
            env['AFL_NO_FORKSRV'] = '1'
        elif 'AFL_NO_FORKSRV' in env:
            del  env['AFL_NO_FORKSRV']
    env[FAKE_EVN_KEY_TO_DETECT_OUR_PROCS] = '1'
    stdout = stderr = bytes('','utf-8')
    tot_bits = 0
    try:
        p = subprocess.Popen( c , shell=True, executable='/bin/bash',  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,cwd=cwd_lib  )
        stdout, stderr = p.communicate(input= bytes('d\n'*100,'utf-8'),timeout=timout)
    except subprocess.TimeoutExpired:
        p.kill()
        if p.poll() is None: stdout = stderr = bytes('','utf-8') 
        #stdout, stderr = p.communicate()
    except Exception as e:
        print(FAIL, 'Could not finish afl-showmap: ', e, ENDC, flush=True)
        return 0

    try:
        for l in open(showmap_file,'r').readlines():
            s = l.strip().split(':')
            if len(s) != 2: continue
            w = int(s[1])
            #print('w:',s, w)
            while w > 0:
                tot_bits += w % 2
                w >>= 1
    except Exception as e:
        print(FAIL, 'ERr:', e, ENDC, flush=True)
        print('STDOUT:', stdout.decode('utf-8', errors='ignore') )
        print('STDERR:', stderr.decode('utf-8', errors='ignore') )
        print(c)

    return tot_bits



#def process_one( fold, tots, cnt, tcnt ):
def process_one( *args ):

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds_per_binary_param)

    try:
        process_one_no_timeout( *args )
    except TimeoutError:
        print('Timeoutt', flush=True)
    finally:
        signal.alarm(0)


def process_one_no_timeout( fold, cnt, tcnt, binary_hashes, cmakefiles_bins, tots, lck  ):

    print("fid: ", cnt, tcnt, flush=True )
    fpath = folder_ubuntu_compiled+fold+'/' + file_extension
    print('crt:',fpath, flush=True)
    with open(fpath,'w') as f:
        pass

    cur_binary_names = set()

    tstart   = time.time()

    # get list of executables already present in the installation folders
    # so later don't mix up with new executable
    exec_pre = list_files( (folder_ubuntu_packs+fold).replace('_defaultc',''), 
                           lambda f: os.path.isfile(f) and  os.access(f, os.X_OK) and is_elf(f),
                           lambda f: os.path.basename(f) )


    # get list of testcases candidates, which is actually all files
    tc_candidates   = []
    probs           = []
    ps              = 0
    for root, dirs, files in os.walk(folder_ubuntu_compiled+fold):
        for file in files:
            f = os.path.join(root, file)
            #print('FILE',f, os.path.isfile(f))
            if os.path.isfile(f):
                tc_size = os.path.getsize(f)
                if tc_size == 0 or tc_size > max_tc_size : 
                    continue
                tc_candidates.append( f )
                #probs.append( 1.0 / math.log(tc_size+10) )   
                probs.append( 1.0 )   
                ps += probs[-1]
    probs = [ probs[i]/ps for i in range(len(probs))]

    #print(tc_candidates)
    if len(tc_candidates) == 0:
        print('cannot find any tc candidates')
        return

    # good files
    good_file_pred = lambda f: \
                            os.path.isfile(f) and os.access(f, os.X_OK) \
                            and is_elf(f) and os.path.basename(f) not in exec_pre \
                            and f[-3:] != '.so' and'.so.' not in f

    tcands      = 0
    gcands      = 0
    bad_fold    = False
    files = list_files( folder_ubuntu_compiled+fold, 
            good_file_pred, 
            lambda x: x)

    # missing libs detected with ldd
    missing_libs = dict()
    missing_cwd = dict()

    print('# Files: ', len(files), flush=True )
    for f in files:

        # try with input file 
        strace_file = '/mnt/c/ivica/fuzz_scale/compile_packages/strace_file.txt'
        strace_file = folder_strace_files + '/' +  fold + '-'+ os.path.basename(f) + '-strace'
        if len(tc_candidates) > 0:
            shutil.copyfile(tc_candidates[0],strace_file)

        # ignore multiple generic files created with CMake
        if 'CMakeFiles' in f:
            if os.path.basename(f) in cmakefiles_bins: continue
            with lck:
                cmakefiles_bins[ os.path.basename(f) ] = 0

        # each binary must have unique name
        if os.path.basename(f) in cur_binary_names: continue
        cur_binary_names.add(os.path.basename(f))

        print('File: ', f, flush=True)
        DEF  = 'defaultc' if 'defaultc' in f else 'defaultq'

        tcands += 1

        conf_has_afl = None
        env = os.environ.copy()
        env['AFL_QEMU_PERSISTENT_GPR']='1'

        # check if it managed to compile with afl-clang 
        afl_binary = f.replace(DEF,'aflpp')
        if os.path.exists(afl_binary):
            try:
                p = subprocess.Popen( "objdump -s "+afl_binary , shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE )
                stdout, stderr = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                if p.poll() is None: stdout = stderr = bytes('','utf-8') 
                #stdout, stderr = p.communicate()
            except Exception as e:
                print('exception in objdump : ',e, flush=True)
            if '__afl_' in stdout.decode('utf-8', errors='ignore'): 
                print(OKGREEN, '[+] Found AFL aflpp instrumentation. ' , afl_binary, ENDC )
                conf_has_afl = 'aflpp'
            else:
                print(FAIL, 'Cannot find __afl_ instrumentation in AFLpp binary', afl_binary, ENDC)
        else:
            print(FAIL, 'No AFLpp binary', ENDC)

        # try with the simpler (manual) afl compilation

        if not conf_has_afl:
            afl_binary = f.replace(DEF,'aflqq')
            if os.path.exists(afl_binary):
                stdout=''
                try:
                    p = subprocess.Popen( "objdump -s "+afl_binary , shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    if p.poll() is None: stdout = stderr = bytes('','utf-8') 
                    #stdout, stderr = p.communicate()
                if '__afl_' in stdout.decode('utf-8', errors='ignore'): 
                    print(OKGREEN, '[+] Found AFL aflqq instrumentation. ' , afl_binary, ENDC )
                    conf_has_afl = 'aflqq'
                else:
                    print(FAIL, 'Cannot find __afl_ instrumentation in AFLqq binary', afl_binary, ENDC)
            else:
                print(FAIL, 'No AFLqq binary', ENDC)



        # make sure not the same file as one previously found
        hfile = hashfile(f)
        if hfile in binary_hashes: continue

        # check dynamic libs
        ld_lib = ''
        try:
            p = subprocess.Popen( 'ldd ' + f , shell=True, executable='/bin/bash', stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
            out, err = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            if p.poll() is None: out = err = bytes('','utf-8') 
            #out, err = p.communicate()
            
        out = out.decode('utf-8', errors='ignore')

        #print('OUT:', outs)
        dyn_libs_missing = []
        tot_path = None
        tot_path_prefix = 0
        relpath = None
        cwd_lib = None
        for l in out.split('\n'):
            if 'not found' in l:
                s = l.split(' ')[0].strip()
                s = re.split(".so",s)[0] + ".so"
                if s != os.path.basename(s):
                    tot_path = s 
                    tot_path_prefix = 0
                    while tot_path[:3] == '../':
                        tot_path_prefix += 1
                        tot_path = tot_path[3:]
                s = os.path.basename(s)
                if len(s) > 0:
                    dyn_libs_missing.append( s )
                print('not found:', s)
        # if more than one missing, just let it go
        if len(dyn_libs_missing) > 1: 
            continue

        # find missing lib (with timeout)
        if len(dyn_libs_missing) == 1:

            print('missing:', missing_libs, dyn_libs_missing[0])

            if dyn_libs_missing[0] not in missing_libs:
                if tot_path is None:
                    search_string = 'find ' + folder_ubuntu_compiled+fold + ' -name '+dyn_libs_missing[0]
                else:
                    search_string = 'find ' + folder_ubuntu_compiled+fold + ' -path *'+tot_path
                try:
                    p = subprocess.Popen( 'find ' + folder_ubuntu_compiled+fold + ' -name '+dyn_libs_missing[0] , shell=True, executable='/bin/bash', stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
                    out, err = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=2)
                    out = out.decode('utf-8', errors='ignore') 
                    print('out:',out)
                except:
                    print('cannot execute find for ', dyn_libs_missing[0] )
                    continue

                mpath = out.split('\n')[0]

                if tot_path is not None:
                    relpath = mpath.replace(tot_path,'')
                    print('rel:', relpath)                    
                    while tot_path_prefix > 0:
                        pos = tot_path.find('/')
                        if pos > 0 :
                            relpath += tot_path[:pos]
                            tot_path = tot_path[pos+1:]
                        tot_path_prefix -= 1
                    print('rel:', relpath)



                if os.path.exists(mpath):
                    missing_libs[dyn_libs_missing[0]] = os.path.dirname(mpath) + \
                        ':' + (relpath if relpath is not None else '')
                else:
                    print('filepath does not exist', mpath)

                if relpath is not None:
                    missing_cwd[dyn_libs_missing[0]] = relpath

            if dyn_libs_missing[0] not in missing_libs:
                continue
            ld_lib = missing_libs[ dyn_libs_missing[0] ]
            cwd_lib = None if dyn_libs_missing[0] not in missing_cwd else missing_cwd[dyn_libs_missing[0]] 
                
            print('ld_lib:',ld_lib)

            if len(ld_lib) > 0:
                if 'LD_LIBRARY_PATH' not in env:
                    env['LD_LIBRARY_PATH'] = ld_lib
                else:
                    env['LD_LIBRARY_PATH'] = ld_lib+":"+env['LD_LIBRARY_PATH']

            # make sure it is good now
            try:
                p = subprocess.Popen( 'ldd ' + f , shell=True, executable='/bin/bash', 
                        stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True, 
                        env=env,cwd=cwd_lib)
                out, err = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=1)
            except subprocess.TimeoutExpired:
                p.kill()
                if p.poll() is None: out = err = bytes('','utf-8') 
                #out, err = p.communicate()

            out = out.decode('utf-8', errors='ignore')
            
            print('totpath', tot_path, tot_path_prefix)
            if 'not found' in out:
                print('cannot find')
                print(env)                
                continue


        # try to get the input params
        outs = ""
        try:
            p = subprocess.Popen( f + ' --help' , shell=True, executable='/bin/bash', stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True, env=env,cwd=cwd_lib)
            out, err = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=1)
            outs += out.decode('utf-8', errors='ignore') 
        except:
            pass
        try:
            p = subprocess.Popen( f + ' -help' , shell=True, executable='/bin/bash', stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True, env=env,cwd=cwd_lib )
            out, err = p.communicate(input=b'one\ntwo\nthree\nfour\nfive\nsix\n',timeout=1)
            outs += out.decode('utf-8', errors='ignore') 
        except:
            pass

            
        diff_params  = []
        for l in outs.split('\n'):

            if '[' in l and ']' in l:
                a = re.findall("\[(.*?)\]", l)
                if a:
                    for o in a: 
                        o = o.strip()
                        if len(o) > 1 and o[0] == '-':
                            ol = re.split('[ \t]', o )
                            o = rem_comma_pipes(ol[0])
                            if o not in diff_params: 
                                diff_params.append( o )
                                print('add diff', l,":", o)


            s = re.split('[ \t]', l.strip() )
            if len(s) > 1 :
                if s[0][0] == '-':
                    sw = rem_comma_pipes(s[0])
                    if sw not in diff_params: 
                        diff_params.append( sw )

        print('Params: ', diff_params, flush=True )


        # find the best input args
        diff_params = ['']+diff_params
        best = None
        #diff_params = ['-r']
        for param in diff_params:

            print('param:' , param, flush=True)

            if time.time() - tstart > seconds_per_binary_param:
                print('breached max secs', flush=True)
                break

            # with strace


            c = '' if cwd_lib is None else 'cd '+cwd_lib+'; ' 
            c+= ' strace -e trace=openat,open ' 
            c+= (f if not conf_has_afl is not None else afl_binary) +' ' +  param + ' ' + strace_file
            #c+= ' 2>&1 | grep ' + strace_file
            c+= ' 2>&1 | grep "openat(\|open("' 
            tot_bits = 0
            timout = 0.5
            try:
                p = subprocess.Popen( c , shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,cwd=cwd_lib  )
                stdout, stderr = p.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                p.kill()
                if p.poll() is None: stdout = stderr = bytes('','utf-8') 
                #stdout, stderr = p.communicate()
            except Exception as e:
                print(FAIL, 'Could not finish strace2: ', e, ENDC, flush=True)
                if is_fuzz_timeout(e):
                    return
                continue

            if strace_file in stdout.decode('utf-8', errors='ignore'):
                tot_bits = get_cov(fold,f,  tc_candidates, probs, afl_binary, conf_has_afl, cwd_lib, param, env, timout)
                print('TOT[param]:', param, tot_bits )
                if best is None or best[1] < tot_bits:
                    best = (param+' @@', tot_bits)
                #break

            # try without input file

            c = '' if cwd_lib is None else 'cd '+cwd_lib+'; ' 
            c+= ' strace -e trace=openat,open,read ' 
            c+= (f if not conf_has_afl is not None else afl_binary) +' ' +  param + ' ' 
            c+= ' 2>&1 ' 
            #print(c)
            try:
                p = subprocess.Popen( c , shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,cwd=cwd_lib  )
                stdout, stderr = p.communicate(timeout=timout)
            except subprocess.TimeoutExpired:
                p.kill()
                if p.poll() is None: stdout = stderr = bytes('','utf-8') 
                #stdout, stderr = p.communicate()
            except Exception as e:
                print(FAIL, 'Could not finish strace1: ', e, ENDC, flush=True)
                if is_fuzz_timeout(e):
                    return
                continue
            if 'read(0,' in stdout.decode('utf-8', errors='ignore'):
                print('Found read:')
                best = (param,0)


        if best is None:
            #best = ('','')
            print(FAIL,'no param reads input file', f, ENDC )
            continue


        # thread-safe update
        with lck:
            tots.value = tots.value+1

        print(WARNING, 'Create ', tots.value, f, ':'+best[0]+':', ENDC, flush=True )

        nf = fuzztarget_folder + '/' + str(tots.value)
        tc = nf + '/testcases'
        sm = nf + '/showmap_tc'
        os.mkdir(nf)
        os.mkdir(tc)
        os.mkdir(sm)

        # copy testcases selected from all files in the source
        ch = numpy.random.choice(tc_candidates, config_no_tc, p=probs )
        tcno = 0
        for one_tc in ch:
            shutil.copyfile(one_tc,tc+'/'+str(tcno))
            tcno +=1

        # copy testcases for showmap
        ch = numpy.random.choice(tc_candidates, config_no_sm, p=probs )
        tcno = 0
        for one_tc in ch:
            shutil.copyfile(one_tc,sm+'/'+str(tcno))
            tcno +=1




        # create file 
        with open(nf+'/fuzz_info.txt','w') as ff:
            ff.write(f+'\n')                                # binary
            #ff.write(' '.join(diff_params) + '\n')
            ff.write(best[0] + '\n')                        # params
            ff.write(conf_has_afl+'\n' if conf_has_afl is not None else '\n')      # good folder for afl binary
            ff.write(DEF+'\n')
            ff.write(ld_lib+'\n')
            ff.write(('' if cwd_lib is None else cwd_lib) + '\n')

        gcands += 1
        with lck:
            binary_hashes[ hfile ] = 0
        if gcands >= 20: 
            break

        if time.time() - tstart > seconds_per_binary_param:
            print('breached max secs', flush=True)
            break

    print(OKCYAN, 'Done id %d / %d : ' % (cnt,tcnt) , tots.value, gcands, tcands, fold, ENDC, flush=True)



if __name__ == '__main__':

    if not os.path.exists(folder_ubuntu_compiled):
        print('cannot find compiled folder', folder_ubuntu_compiled)
        exit()


    file_extension = 'proc_fuzz'

    FAKE_EVN_KEY_TO_DETECT_OUR_PROCS = 'FUZZR_PROC'

    config_no_tc = 50
    config_no_sm = 4
    cur_folder_abs = os.getcwd() 

    seconds_per_binary_param = 300       # needs to be integer !



    folder_temp_showmaps = cur_folder_abs + '/temp_showmaps'
    if os.path.exists(folder_temp_showmaps):
        shutil.rmtree(folder_temp_showmaps)
    os.mkdir(folder_temp_showmaps)

    folder_strace_files = cur_folder_abs + '/temp_strace'
    if os.path.exists(folder_strace_files):
        shutil.rmtree(folder_strace_files)
    os.mkdir(folder_strace_files)



    start_id = 0
    fuzztarget_folder = cur_folder_abs+'/fuzz_targets' 
    if os.path.exists(fuzztarget_folder):
        for d in glob.glob(fuzztarget_folder+'/**'):
            d = d.replace(fuzztarget_folder+'/','')
            if str_to_int(d) >= start_id:
                start_id = str_to_int(d) + 1
            print(d)
        #shutil.rmtree(fuzztarget_folder)
    else:
        os.mkdir(fuzztarget_folder)


    mang            = multiprocessing.Manager()
    binary_hashes   = mang.dict()
    cmakefiles_bins = mang.dict()
    tots            = mang.Value('i',start_id)

    Lck             = mang.Lock()


    # compress folder and copy 
    alldirs = []
    for f in glob.glob(folder_ubuntu_compiled + '/*'):
        if os.path.isdir(f):
            #if 'sdcc' not in f: continue
            if '_defaultc' not in f: continue                # check only compiled with default compiler       
            if os.path.exists(f+'/' + file_extension): continue # already processed
            alldirs.append( os.path.basename(f) )

    print('Tot:', len(alldirs))

    cnt = 0
    for i in range(len(alldirs)):
        cnt += 1
        alldirs[i]= ( alldirs[i], cnt, len(alldirs), binary_hashes, cmakefiles_bins, tots, Lck  )

    print('starting...', flush=True)
    pool = multiprocessing.pool.Pool(no_cpu, maxtasksperchild=1 ) 
    pool.starmap_async(process_one, alldirs, chunksize=1 )
    pool.close()
    pool.join()

