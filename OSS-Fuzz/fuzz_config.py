import os

folder_afl              = os.getenv('BOIAN_AFL')
folder_aflpp            = os.getenv('BOIAN_AFLPP')

if folder_afl is None: raise EnvironmentError(f'Required environment variable "BOIAN_AFL" is not set.')
if folder_aflpp is None: raise EnvironmentError(f'Required environment variable "BOIAN_AFLPP" is not set.')

no_cpu                  = os.cpu_count() - 1

# make sure all folders exist
for f in [folder_afl, folder_aflpp]:
    if not os.path.exists(f):
        print(FAIL + f"{f} does not exist" + ENDC)
        exit(1)

folder_main	            = os.path.dirname(os.path.abspath(__file__))
 
folder_oss_projects     = folder_main  + '/oss-fuzz/projects/'
folder_oss_compiled     = folder_main  + '/compiled/'


HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'



