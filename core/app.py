from enum import Enum
import json
import re
import os
from core.androhelper import AndroHelper
from config import main


class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


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
        self.malware_confidence = 0
        self.score = 0

    def check_app(self):
        if self.dump_apk:
            if not os.path.isdir(self.out_dir):
                os.mkdir(self.out_dir)
            try:
                out_file = self.out_dir + "/" + self.package_name + ".apk"
                self.adb_instance.dump_apk_from_device(self.package_name, out_file)
            except Exception as e:
                return None, None, None, None

        if self.scan:
            perm_desc, self.dangerous_perms = self.check_perms()
            return perm_desc, self.dangerous_perms, self.is_app_device_owner(), self.known_malware()

        return None, None, None, self.known_malware()

    def check_perms(self):
        with open(main.PERMISSIONS_FILE) as json_file:
            permissions = json.load(json_file)

        perms_desc = {}
        self.dangerous_perms = {}
        self.malware_perms_detect(self.perms_list)

        for perm in self.perms_list:
            try:
                mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                    # Permission is flagged as dangerous
                    self.dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

            except Exception as e:
                continue

        return perms_desc, self.dangerous_perms

    # check if package_name is device owner
    def is_app_device_owner(self):
        if self.package_name in self.device_policy_out:
            return True
        return False

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

    def malware_perms_detect(self, perms):
        with open(main.MALWARE_PERMS) as json_file:
            malware_perms = json.load(json_file)

        if not perms:
            return 0

        for perm in perms:
            # check malware only permissions
            for p in malware_perms["malware_only"]:
                if perm.split(".")[-1] == p:
                    self.malware_confidence = self.malware_confidence + 1

        # check permissions combinations
        for nb in malware_perms["combinations"]:
            for p in malware_perms["combinations"][nb]:

                if set(p["permissions"]).issubset(set([item.split(".")[-1] for item in perms])):
                    self.malware_confidence = self.malware_confidence + 1

        dict_all_perms = malware_perms["all"]
        sum_malware = 0
        sum_benign = 0
        for perm in perms:
            current_perm = perm.split(".")[-1]
            if current_perm in dict_all_perms.keys():
                sum_malware = sum_malware + dict_all_perms[current_perm]["malware"]
                sum_benign = sum_benign + dict_all_perms[current_perm]["benign"]

        self.score = sum_benign - sum_malware

    def static_analysis(self):
        if self.dump_apk:
            if not os.path.isdir(self.out_dir):
                os.mkdir(self.out_dir)

            out_file = self.out_dir + "/" + self.package_name + ".apk"
            self.adb_instance.dump_apk_from_device(self.package_name, out_file)

            # output directory for embedded files: "out_dir/package_name/"
            androhelper = AndroHelper(out_file, self.out_dir + "/" + self.package_name)

            return androhelper.analyse()

    def known_malware(self):
        with open(main.MALWARE_PACKAGES_FILE) as json_file:
            malware_packages = json.load(json_file)

        if self.package_name in malware_packages["packages"]:
            return True

        return False
