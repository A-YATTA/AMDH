import re
from threading import Thread
import time
import json

from core.app import Status


class Snapshot:

    def __init__(self, adb_instance, app_type=Status.THIRD_PARTY.value, out_dir="out",
                 snapshot_file="report.json", backup=True):
        self.adb_instance = adb_instance
        self.out_dir = out_dir
        self.app_type = app_type
        self.report = dict()
        self.snapshot_file = snapshot_file
        self.backup = backup

    def snapshot_packages(self):
        packages = self.adb_instance.list_installed_packages(self.app_type)
        self.report["apps"] = dict()
        for package in packages:
            dumpsys_package = self.adb_instance.dumpsys(['package', package])
            self.report["apps"][package] = dict()
            self.report["apps"][package]["firstInstallTime"] = self.adb_instance.get_package_first_install_time(package)
            self.report["apps"][package]["lastUpdateTime"] = self.adb_instance.get_package_last_update_time(package)
            self.report["apps"][package]["grantedPermissions"] = self.adb_instance.get_req_perms_dumpsys_package(
                dumpsys_package)

            if package in self.adb_instance.dumpsys(["device_policy"]):
                self.report["apps"][package]["deviceAdmin"] = True
            else:
                self.report["apps"][package]["deviceAdmin"] = False

            if self.backup and "ALLOW_BACKUP" in re.search(r"flags=(.*)", dumpsys_package).group(1):
                # Application allow backup
                # TODO: backup password
                output = self.out_dir + "/" + package + ".ab"
                self.__backup__(package, output)
                self.report["apps"][package]["backup"] = package + ".ab"

        return self.report["apps"]

    def snapshot_settings(self):
        self.report["settings"] = dict()
        global_settings = self.adb_instance.get_all_settings_section("global")
        self.report["settings"]["global"] = dict(x.split("=", 1) for x in global_settings.split("\n") if x.strip())

        secure_settings = self.adb_instance.get_all_settings_section("secure")
        self.report["settings"]["secure"] = dict(x.split("=", 1) for x in secure_settings.split("\n") if x.strip())

        system_settings = self.adb_instance.get_all_settings_section("system")
        self.report["settings"]["system"] = dict(x.split("=", 1) for x in system_settings.split("\n") if x.strip())

    def snapshot_sms(self):
        sms_ids = self.adb_instance.get_content_sms_projection("_id", "1=1")
        self.report["sms"] = dict()
        if not sms_ids or "No result found." in sms_ids:
            return self.report["sms"]

        for sms_id in sms_ids.split("\n"):
            if not sms_id:
                break
            sms_id = self.__remove_row_projection__(sms_id)

            self.report["sms"][sms_id] = dict()

            address = self.__remove_row_projection__(self.adb_instance.get_content_sms_projection(
                                                                                "address", "'_id=" + sms_id + "'"))
            date = self.__remove_row_projection__(self.adb_instance.get_content_sms_projection(
                                                                                "date", "'_id=" + sms_id + "'"))
            date_sent = self.__remove_row_projection__(self.adb_instance.get_content_sms_projection(
                                                                                "date_sent", "'_id=" + sms_id + "'"))
            body = self.__remove_row_projection__(self.adb_instance.get_content_sms_projection(
                                                                                "body", "'_id=" + sms_id + "'"))
            seen = self.__remove_row_projection__(self.adb_instance.get_content_sms_projection(
                                                                                "seen", "'_id=" + sms_id + "'"))

            self.report["sms"][sms_id] = {"address": address, "date": date, "date_sent": date_sent, "body": body,
                                          "seen": seen}

        return self.report["sms"]

    def snapshot_contacts(self):
        contatcts_result = self.adb_instance.get_content_contacts()
        self.report["contacts"] = dict()

        if not contatcts_result or "No result found." in contatcts_result:
            return self.report["contacts"]

        id = 1
        for contact in re.split("Row: [0-9]* ", contatcts_result):
            self.report["contacts"][str(id)] = \
                dict(map(str.strip, sub.split('=', 1)) for sub in contact.strip().split(', ') if '=' in sub)
            id += 1

        return self.report["contacts"]

    def get_report(self):
        self.report = dict()
        if self.backup:
            self.snapshot_packages()
            self.snapshot_settings()
            self.snapshot_sms()
            self.snapshot_contacts()
        else:
            self.snapshot_compare()

        return self.report

    def __backup__(self, package, output):
        thread_backup = Thread(target=self.adb_instance.backup, args=(package, output))
        thread_backup.start()
        time.sleep(0.5)
        # password field
        self.adb_instance.send_keyevent(61)
        # DO NOT BACKUP
        self.adb_instance.send_keyevent(61)
        # BACKUP
        self.adb_instance.send_keyevent(61)
        # Confirm
        self.adb_instance.send_keyevent(66)
        thread_backup.join()

    def __remove_row_projection__(self, string):
        return re.split("Row: [0-9]* ", string)[1].strip().split("=")[1]

    def snapshot_compare(self):
        return {"apps": self.cmp_snapshot_apps(), "settings": self.cmp_snapshot_settings()}

    def cmp_snapshot_apps(self):
        with open(self.snapshot_file) as json_file:
            snap_apps = json.load(json_file)["apps"]

        current_apps = self.snapshot_packages()

        apps_exist_in_snap = dict()
        new_installed_apps = dict()
        uninstalled_apps = dict()

        for installed_app in current_apps.keys():
            if installed_app in snap_apps:
                apps_exist_in_snap.update({installed_app: current_apps[installed_app]})
            else:
                new_installed_apps.update({installed_app: current_apps[installed_app]})

        if len(snap_apps) > len(current_apps):
            uninstalled_apps.update({app: snap_apps[app] for app in set(snap_apps) - set(current_apps)})
        else:
            uninstalled_apps.update({app: current_apps[app] for app in set(current_apps) - set(snap_apps)})

        report = dict()
        report["new_installed_apps"] = new_installed_apps
        report["apps_exist_in_snap"] = apps_exist_in_snap
        report["uninstalled_apps"] = uninstalled_apps
        return report

    def cmp_snapshot_settings(self):
        changed_keys = dict()

        with open(self.snapshot_file) as json_file:
            snap_settings = json.load(json_file)["settings"]

        current_global_settings = dict(x.split("=", 1) for x in
                                       self.adb_instance.get_all_settings_section("global").split("\n") if x.strip())
        current_secure_settings = dict(x.split("=", 1) for x in
                                       self.adb_instance.get_all_settings_section("secure").split("\n") if x.strip())
        current_system_settings = dict(x.split("=", 1) for x in
                                       self.adb_instance.get_all_settings_section("system").split("\n") if x.strip())



        # Global settings
        changed_keys["global"] = []

        for key in snap_settings["global"].keys():
            if key in current_global_settings:
                current_value = current_global_settings[key]

                if current_value != snap_settings["global"][key]:
                    changed_keys["global"].append(key)

        # Secure settings
        changed_keys["secure"] = []
        for key in snap_settings["secure"]:
            if key in current_secure_settings:
                current_value = current_secure_settings[key]

                if current_value != snap_settings["secure"][key]:
                    changed_keys["secure"].append(key)

        # System settings
        changed_keys["system"] = []
        for key in snap_settings["system"]:
            if key in current_system_settings:
                current_value = current_system_settings[key]

                if current_value != snap_settings["system"][key]:
                    changed_keys["system"].append(key)

        return changed_keys



