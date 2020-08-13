from core.adb import ADB
from core.app import Status

class Snapshot:

    def __init__(self, adb_instance):
        self.adb_instance = adb_instance
        self.report = dict()


    def snapshot_packages(self):

        packages = self.adb_instance.list_installed_packages(Status.ENABLED.value)
        disabled_packages = self.adb_instance.list_installed_packages(Status.DISABLED.value)

        packages = packages + disabled_packages

        for package in packages:
            self.report[package] = dict()
            self.report[package]["firstInstallTime"] = self.adb_instance.get_package_first_install_time(package)
            self.report[package]["lastUpdateTime"] = self.adb_instance.get_package_last_update_time(package)
            dumpsys_package = self.adb_instance.dumpsys(['package', package])
            self.report[package]["grantedPermissions"] = self.adb_instance.get_req_perms_dumpsys_package(dumpsys_package)

            if package in self.adb_instance.dumpsys(["device_policy"]):
                self.report[package]["deviceAdmin"] = True
            else:
                self.report[package]["deviceAdmin"] = False



    def snapshot_settings(self):
        self.report["settings"] = dict()
        global_settings = self.adb_instance.get_all_settings_section("global")
        self.report["settings"]["global"] = dict(x.split("=", 1) for x in global_settings.split("\n") if x.strip())

        secure_settings =  self.adb_instance.get_all_settings_section("secure")
        self.report["settings"]["secure"] = dict(x.split("=", 1) for x in secure_settings.split("\n") if x.strip())

        system_settings = self.adb_instance.get_all_settings_section("system")
        self.report["settings"]["system"] = dict(x.split("=", 1) for x in system_settings.split("\n") if x.strip())

    def snapshot_sms(self):
        self.report["sms"] = self.adb_instance.get_content_sms()

    def snapshot_contacts(self):
        self.report["contacts"] = self.adb_instance.get_content_contacts()


    def get_report(self):
        self.report = dict()
        self.snapshot_packages()
        self.snapshot_settings()
        self.snapshot_sms()
        self.snapshot_contacts()

        return self.report






