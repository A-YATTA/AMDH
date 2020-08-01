from androguard.misc import AnalyzeAPK
import re
import json


permissions_file = "config/permissions.json"


def check_header(header):
    if header == "504b0304":
        return "JAR"

    return "UNKNOWN"




class AndroHelper:

    def __init__(self, apk_path):
        self.apk_path = apk_path
        #TO-DO verify path exist
        self.a, self.d, self.dx = AnalyzeAPK(self.apk_path)


    def check_files(self):
        for file in self.a.get_files():
            file_type = check_header(self.a.get_file(file)[0:4].hex())

            if file_type == "JAR":
                print("JAR file Founded: " + file.split("/")[-1])
                f = open(file.split("/")[-1], 'wb')
                f.write(self.a.get_file(file))
                f.close()
                a, d, dx = AnalyzeAPK(file.split("/")[-1])

                with open(permissions_file) as json_file:
                    permissions = json.load(json_file)
                perms_desc = {}
                dangerous_perms = {}

                for perm in a.get_permissions():
                    try:
                        mapped = list(filter(lambda x: x["permission"] == perm, permissions))
                        perms_desc[perm] = {"desc": mapped[0]["desc"], "level": mapped[0]["protection_lvl"]}
                        if any(re.findall(r'dangerous', mapped[0]["protection_lvl"], re.IGNORECASE)):
                            # Permission is flagged as dangerous
                            dangerous_perms[mapped[0]["permission"]] = mapped[0]["desc"]

                    except Exception as e:
                        continue

                return file, perms_desc, dangerous_perms









