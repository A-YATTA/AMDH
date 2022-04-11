
class BColors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    WARNING_HEADER = '\033[33m'
    UNDERLINE = '\033[4m'


class Out:
    def __init__(self, platform="Linux", filename=None):
        self.platform = platform
        self.log = None
        if filename:
            self.log = open(filename, "w")

    def print(self, message):
        if self.log:
            self.log.write(f"{message}\n")
            return

        print(f"{message}\n")

    def print_info(self, message):
        if self.log:
            self.log.write("[-] INFO: %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.INFO + "[-] INFO: " + BColors.ENDC + f"{message}")
        else:
            print("[-] INFO: " + f"{message}")

    def print_warning(self, message):
        if self.log:
            self.log.write("[!] WARNING: %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.WARNING + "[!] WARNING: " + f"{message}" + BColors.ENDC)
        else:
            print("[!] WARNING: " + f"{message}")

    def print_warning_header(self, message):
        if self.log:
            self.log.write("[!] WARNING: %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.WARNING_HEADER + "[!]  " + f"{message}" + BColors.ENDC)
        else:
            print("[!] WARNING: " + f"{message}")

    def print_error(self, message):
        if self.log:
            self.log.write("[X] ERROR: %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.FAIL + "[X] ERROR: " + f"{message}" + BColors.ENDC)
        else:
            print("[X] ERROR: " + f"{message}")

    def print_success(self, message):
        if self.log:
            self.log.write("[+] OK: %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.OKGREEN + "[+] OK: " + f"{message}" + BColors.ENDC)
        else:
            print("[+] OK: " + f"{message}")

    def print_high_warning(self, message):
        if self.log:
            self.log.write("[!] WARNING (HIGH): %s\n" % message)
            return

        if self.platform == "Linux" or self.platform == "Darwin":
            print(BColors.FAIL + "[!] WARNING: " + f"{message}" + BColors.ENDC)
        else:
            print("[!] WARNING (HIGH): %s" % message)
