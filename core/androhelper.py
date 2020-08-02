from androguard.misc import AnalyzeAPK
import re
import json
import os

permissions_file = "config/permissions.json"



def check_header(header):
    if header == "504b0304":
        return "JAR"

    return "UNKNOWN"




class AndroHelper:

    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path

        # output directory

        self.output_dir = output_dir + "/"

        self.a, self.d, self.dx = AnalyzeAPK(self.apk_path)

    def check_files(self):
        packed_files = dict()
        for file in self.a.get_files():
            file_type = check_header(self.a.get_file(file)[0:4].hex())

            if not os.path.isdir(self.output_dir):
                os.makedirs(self.output_dir)

            if file_type == "JAR":
                print("Probable JAR file Founded: " + file.split("/")[-1])

                f = open(self.output_dir + file.split("/")[-1], 'wb')
                f.write(self.a.get_file(file))
                f.close()
                try:
                    a, d, dx = AnalyzeAPK(self.output_dir + file.split("/")[-1])



                    if a.get_package():
                        packed_files[self.a.get_package()] = {file: {}}
                    else:
                        continue
                except Exception as e:  # not apk file
                    continue

                with open(permissions_file) as json_file:
                    permissions = json.load(json_file)
                perms_desc = {}
                dangerous_perms = {}

                if a .get_permissions():
                    for perm in a.get_permissions():
                        try:
                            mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                            perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                            if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                                # Permission is flagged as dangerous
                                dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

                        except Exception as e:
                            continue

                packed_files[self.a.get_package()][file] = dangerous_perms

        return packed_files











