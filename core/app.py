from enum import Enum
import json
import re
import os
from utils.out import *


# Status of the App
class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


perms_combination_file = "perms_combination.json"
permissions_file = "config/permissions.json"


class App:
    def __init__(self, adb_instance, package_name, dump_apk=False, out_dir="apks_dump", perms_list={}):
        self.adb_instance = adb_instance
        self.package_name = package_name
        self.out_dir = out_dir
        self.perms_list = perms_list
        self.dump_apk = dump_apk

    def check_apps(self):
        packages = self.adb_instance.list_installed_packages(Status.THIRD_PARTY.value)
        print_info(self.package_name)
        if self.dump_apk:
            if not os.path.isdir(self.out_dir):
                os.mkdir(self.out_dir)

            out_file = self.out_dir + "/" + self.package_name + ".apk"
            self.adb_instance.dump_apk_from_device(self.package_name, out_file)

        perm_desc, dangerous_perms = self.check_perms()

        return perm_desc, dangerous_perms

    def check_perms(self):
        with open(permissions_file) as json_file:
            permissions = json.load(json_file)
        perms_desc = {}
        dangerous_perms = {}
        for perm in self.perms_list:
            try:
                mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                    dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

            except Exception as e:

                continue
        return perms_desc, dangerous_perms


