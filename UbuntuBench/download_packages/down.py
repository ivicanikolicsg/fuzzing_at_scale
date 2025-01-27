import multiprocessing, os, subprocess, glob, shutil, sys, psutil

pack_folder = r'./packs/' 
if not os.path.exists(pack_folder):
    os.makedirs(pack_folder)

def down_one(pack):
    q = 'cd '+pack_folder+' ; apt-get source '+pack
    p = subprocess.Popen( q , shell=True )
    stdout, stderr = p.communicate()
    print(stdout,stderr)


all_packs = [o.strip() for o in open('all_packages.txt','r') ]

remove_prefix=['linux-','python','ubuntu','texlive','ruby-','r-cran','php-','nvidia']
remove_prefix+=['node-','lua-','llvm-','language-','golang-','gobjc','gnome-','gfortran-']
remove_prefix+=['gdc-','gcc','g++','fonts-','firefox','elpa-','dict-']
for prefix in remove_prefix:
    all_packs = [a for a in all_packs if prefix != a[:len(prefix)] ]


no_cpu = os.cpu_count() - 1
pool = multiprocessing.Pool(no_cpu)
pool.map_async(down_one,all_packs)
pool.close()
pool.join()

