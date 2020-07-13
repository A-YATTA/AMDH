from utils.out import *
import json

settings_file = "config/settings.json"

class Settings:

    def __init__(self, json_settings_file, adb, harden=False):
        self.json_settings_file = json_settings_file
        self.adb = adb
        self.harden = harden
        self.result_scan = dict()

    def check(self):
        with open(settings_file) as settingsFile:
            settings = json.load(settingsFile)

        print_info("++++++++++++++++++++++++++++++++++++++++++++++++")
        print_info("+           Checking Secure Settings           +")
        print_info("++++++++++++++++++++++++++++++++++++++++++++++++")

        self.loop_settings_check("secure", settings)

        print_info("++++++++++++++++++++++++++++++++++++++++++++++++")
        print_info("+            Checking Global Settings          +")
        print_info("++++++++++++++++++++++++++++++++++++++++++++++++")

        self.loop_settings_check("global", settings)




    def loop_settings_check(self, section, settings):
        for a in settings[section]:
            command_result = self.adb.content_query(section, a["name"])

            print_info("Checking : " + a["name"])
            print_info("\tDescription : " + a["description"])
            print_info("\tExpected : " + a["expected"])

            if "No result found" in command_result:
                print_warning("\tKey does not exist\n")
                self.append_key_to_result_scan_dict(section, {a["name"]: "key not found"})

            elif command_result.split("value=")[1].strip() == a["expected"].strip():

                print_success("\tCurrent value : " + command_result.split("value=")[1].strip() + "\n")
                self.append_key_to_result_scan_dict(section, {a["name"]: command_result.split("value=")[1].strip()})

            else:
                if self.harden:
                    self.adb.content_insert(section, a["name"], expected_value=a["expected"],
                                            expected_value_type=a["type"])
                    print_warning("\tCurrent value : " + str(command_result.split("value=")[1].strip()) + "\n")
                    print_success("\tValue changed to: " + a["expected"] + "\n")
                else:
                    print_warning("\tCurrent value : " + str(command_result.split("value=")[1].strip()) + "\n")
                    self.append_key_to_result_scan_dict(section, {a["name"]: command_result.split("value=")[1].strip()})

    def get_scan_report(self, section):
        if self.result_scan[section]:
            return self.result_scan[section]
        return {}

    def append_key_to_result_scan_dict(self, key, value):
        if key in self.result_scan:
            self.result_scan[key].append(value)

        else:
            self.result_scan[key] = [value]


