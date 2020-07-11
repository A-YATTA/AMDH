

class bcolors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    WARNING_HEADER = '\033[33m'
    UNDERLINE = '\033[4m'

def print_info(message):
    print(bcolors.INFO + "[-] INFO: " + bcolors.ENDC + f"{message}" )


def print_warning(message):
    print(bcolors.WARNING + "[!] WARNING: " + f"  {message}" + bcolors.ENDC)

def print_warning_header(message):
    print(bcolors.WARNING_HEADER + "[!] " + f"  {message}" + bcolors.ENDC)

def print_error(message):
    print(bcolors.FAIL + "[X] ERROR: " + f"  {message}" + bcolors.ENDC)


def print_success(message):
    print(bcolors.OKGREEN + "[+] OK: " + f"  {message}" + bcolors.ENDC)


