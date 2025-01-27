import multiprocessing, os, subprocess, glob, shutil, sys, psutil
sys.path.append("../")
from fuzz_config import *


# create the debian folder for mk-build-deps
if not os.path.exists('debian'):
    os.mkdir( 'debian' )


sects = dict()
count = 0
for f in glob.glob(folder_ubuntu_packs + '/*'):
    if os.path.isdir(f):

        control = f + '/debian/control'
        if not os.path.exists(control): 
            continue

        lines = [ x for x in open(control,'r').readlines() ]

        section = None
        build_deps = None
        for i in range(len(lines)):
            l = lines[i]
            if section is None and 'Section:' == l[0:len('Section:')]:
                section = l[len('Section:'):].strip()
            if  section is not None and \
                build_deps is None and \
                'Build-Depends:' == l[0:len('Build-Depends:')]:
                    build_deps = l[len('Build-Depends:'):].strip()
                    j = i+1
                    while j < len(lines) and lines[j][0] in [' ','\t']:
                        z = lines[j].strip()
                        if len(z)> 0:
                            build_deps += z
                        j += 1

                    if section not in sects:
                        sects[section] = set()

                    sects[section] = sects[section].union(set([ x for x in build_deps.split(',') if len(x) > 0 ]))



for s in sects:
    print('\n\n',s, sects[s])


cnt = 0
for s in sects:
    output = open('debian/control','w')
    output.write('Source: alldeps\n')
    output.write('Section: '+s+'\n')
    output.write('Build-Depends: ')
    output.write( ',\n\t'.join(list(sects[s])) )
    output.close()

    cnt += 1
    print('\n\n' + '#'*50 + '   ' + str(cnt)+' / ' + str(len(sects)) + '  ' + s )

    try:
        p = subprocess.Popen( 'sudo mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" -i' , shell=True, executable='/bin/bash' )
        stdout, stderr = p.communicate() #(timeout=300)
    except:
        print('Timeout')


    