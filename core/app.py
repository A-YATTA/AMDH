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


class AppAction(Enum):
    UNINSTALL = 'u'
    DISABLE = 'd'
    NONE = 'n'

perms_combination_file = "perms_combination.json"
permissions_file = "config/permissions.json"


class App:
    def __init__(self, adb_instance, package_name, scan=True, dump_apk=False, out_dir="apks_dump", perms_list={}):
        self.adb_instance = adb_instance
        self.package_name = package_name
        self.out_dir = out_dir
        self.perms_list = perms_list
        self.dump_apk = dump_apk
        self.device_policy_out = self.adb_instance.dumpsys(["device_policy"])
        self.dangerous_perms = None
        self.scan = scan

    def check_app(self):
        packages = self.adb_instance.list_installed_packages(Status.THIRD_PARTY.value)
        if self.dump_apk:
            if not os.path.isdir(self.out_dir):
                os.mkdir(self.out_dir)

            out_file = self.out_dir + "/" + self.package_name + ".apk"
            self.adb_instance.dump_apk_from_device(self.package_name, out_file)

        if self.scan:
            perm_desc, self.dangerous_perms = self.check_perms()
            return perm_desc, self.dangerous_perms, self.is_app_device_owner()

        return None, None, None

    def check_perms(self):
        with open(permissions_file) as json_file:
            permissions = json.load(json_file)
        perms_desc = {}
        self.dangerous_perms = {}
        for perm in self.perms_list:
            try:
                mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                    self.dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

            except Exception as e:
                continue

        return perms_desc, self.dangerous_perms

    # check if package_name is device owner
    def is_app_device_owner(self):
        if self.package_name in self.device_policy_out:
            return True

    def remove_device_admin_for_app(self):
        device_admin_receivers = re.findall(r"(" + self.package_name + ".*):", self.device_policy_out)
        for device_admin_receiver in device_admin_receivers:
            try:
                self.adb_instance.remove_dpm(device_admin_receiver)
                return True, device_admin_receiver
            except Exception as e:
                return False, device_admin_receiver


    def revoke_dangerous_perms(self):
        for perm in self.dangerous_perms:
            try:
                self.adb_instance.revoke_perm_pkg(self.package_name, perm)
            except Exception as e:
                continue
        return True
