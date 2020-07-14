
class bcolors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    WARNING_HEADER = '\033[33m'
    UNDERLINE = '\033[4m'


class Out:
    def __init__(self, platform):
        self.platform = platform

    def print_info(self ,message):
        if self.platform == "Linux" or self.platform == "Darwin":
            print(bcolors.INFO + "[-] INFO: " + bcolors.ENDC + f"{message}" )
        else:
            print("[-] INFO: " + f"{message}")


    def print_warning(self, message):
        if self.platform == "Linux" or self.platform == "Darwin":
            print(bcolors.WARNING + "[!] WARNING: " + f"{message}" + bcolors.ENDC)
        else:
            print("[!] WARNING: "  + f"{message}")

    def print_warning_header(self, message):
        if self.platform == "Linux" or self.platform == "Darwin":
            print(bcolors.WARNING_HEADER + "[!]  " + f"{message}" + bcolors.ENDC)
        else:
            print("[!] WARNING: " + f"{message}")


    def print_error(self, message):
        if self.platform == "Linux" or self.platform == "Darwin":
            print(bcolors.FAIL + "[X] ERROR: " + f"{message}" + bcolors.ENDC)
        else:
            print("[X] ERROR: " + f"{message}")

    def print_success(self, message):
        if self.platform == "Linux" or self.platform == "Darwin":
            print(bcolors.OKGREEN + "[+] OK: " + f"{message}" + bcolors.ENDC)
        else:
            print("[+] OK: " + f"{message}")
