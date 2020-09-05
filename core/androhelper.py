from androguard.misc import AnalyzeAPK
import re
import json
import os
from core.malware.actionSpy import ActionSpy
from core.malware.wolfRat import WolfRat
from core.malware.anubis import Anubis
from core.malware.utils import check_header
from config.main import *


class AndroHelper:

    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        # output directory
        self.output_dir = output_dir + "/"
        self.packed_files = dict()
        self.a, self.d, self.dx = AnalyzeAPK(self.apk_path)
        self.detected_malware = dict()

    @property
    def analyse(self):
        self.packed_files = dict()
        self.malware_detect()

        for file in self.a.get_files():
            file_type = check_header(self.a.get_file(file)[0:4].hex())

            if file_type == "JAR":

                if not os.path.isdir(self.output_dir):
                    os.makedirs(self.output_dir)

                f = open(self.output_dir + file.split("/")[-1], 'wb')
                f.write(self.a.get_file(file))
                f.close()
                try:
                    a, d, dx = AnalyzeAPK(self.output_dir + file.split("/")[-1])

                    if a.get_package():
                        self.packed_files[self.a.get_package()] = {file: {}}
                    else:
                        continue
                except Exception as e:  # not apk file
                    continue

                with open(PERMISSIONS_FILE) as json_file:
                    permissions = json.load(json_file)
                perms_desc = {}
                dangerous_perms = {}

                if a.get_permissions():
                    for perm in a.get_permissions():
                        try:
                            mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                            perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                            if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                                # Permission is flagged as dangerous
                                dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

                        except Exception as e:
                            continue

                self.packed_files[self.a.get_package()][file] = dangerous_perms

        return {"packed_file": self.packed_files, "detected_malware": self.detected_malware}


    def malware_detect(self):
        action_spy = ActionSpy(apk_path=self.apk_path, output_dir=self.output_dir)
        succeeded_test = action_spy.check()
        self.detected_malware["actionspy"] = succeeded_test

        wolf_rat = WolfRat(apk_path=self.apk_path, output_dir=self.output_dir)
        succeeded_test = wolf_rat.check()
        self.detected_malware["wolfrat"] = succeeded_test

        anubis = Anubis(apk_path=self.apk_path, output_dir=self.output_dir)
        succeeded_test = anubis.check()
        self.detected_malware["anubis"] = succeeded_test


