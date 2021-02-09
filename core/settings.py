import json
from enum import Enum

from config.main import *
from utils.out import Out


class SettingTest(Enum):
    PASSED = 'passed'
    FAILED = 'failed'
    HARDENED = 'changed'


class Settings:

    def __init__(self, json_settings_file, adb, harden=False, out=Out()):
        self.json_settings_file = json_settings_file
        self.adb = adb
        self.harden = harden
        self.out = out
        self.result_scan = dict()

    def check(self):
        with open(SETTINGS_FILE) as settingsFile:
            settings = json.load(settingsFile)

        for key, value in settings.items():
            self.out.print_info("++++++++++++++++++++++++++++++++++++++++++++++++")
            self.out.print_info(f"+           Checking {key} Settings           +")
            self.out.print_info("++++++++++++++++++++++++++++++++++++++++++++++++")
            self.loop_settings_check(key, value)

        return self.result_scan

    def loop_settings_check(self, section, settings):
        for setting in settings:
            command_result = self.adb.content_query_settings(section, setting["name"])

            self.out.print_info("Checking : " + setting["name"])
            self.out.print_info("\tDescription : " + setting["description"])
            self.out.print_info("\tExpected : " + setting["expected"])

            if "No result found" in command_result:
                self.out.print_warning("\tKey does not exist\n")
                self.append_key_to_result_scan_dict(section, {setting["name"]: "key not found"})

            elif command_result.split("value=")[1].strip() == setting["expected"].strip():
                self.append_key_to_result_scan_dict(section,
                                                    {
                                                        setting["name"]:
                                                            {
                                                                "description": setting["description"],
                                                                "test": SettingTest.PASSED.value
                                                             }
                                                    })

                self.out.print_success("\tCurrent value : " + command_result.split("value=")[1].strip() + "\n")
            else:
                self.out.print_warning("\tCurrent value : " + str(command_result.split("value=")[1].strip()) + "\n")
                test = SettingTest.FAILED.value
                if self.harden:
                    self.adb.content_insert_settings(section, setting["name"], expected_value=setting["expected"],
                                                     expected_value_type=setting["type"])
                    self.out.print_warning("\tModified : " + setting["expected"] + "\n")
                    test = f"{SettingTest.FAILED.value}|{SettingTest.HARDENED.value}"

                self.append_key_to_result_scan_dict(section,
                                                    {
                                                        setting["name"]:
                                                            {
                                                                "description": setting["description"],
                                                                "test": test
                                                            }
                                                    })

        return self.result_scan

    def get_scan_report(self, section):
        if self.result_scan[section]:
            return self.result_scan[section]
        return {}

    def append_key_to_result_scan_dict(self, key, value):
        if key in self.result_scan:
            self.result_scan[key].append(value)
        else:
            self.result_scan[key] = [value]


