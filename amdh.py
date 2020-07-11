from adb import ADB
from out import *
from settings import Settings
from enum import Enum
import argparse
from app import App
from argparse import RawTextHelpFormatter

adb_path = "/usr/bin/adb"
settings_file = "settings.json"


def args_parse():
    parser = argparse.ArgumentParser(description='Android Mobile Device Hardening\nBy default the script will scan ' + \
                                                 'the Android system and Apps without any modification',
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument('-H', help='Harden system settings /!\ Developer Options and ADB will be disabled /!\ ',
                        action='store_true')
    parser.add_argument('-a', '--adb-path', help='Path to ADB binary', default="/usr/bin/adb", dest="adb_path")
    """parser.add_argument('-d', '--device', help='Device id (check "adb list-devices"). If none the script will list ' + \
                                               'current connected devices', dest="device_id", action='store_true')"""
    parser.add_argument('-t', choices=['e', 'd', '3', 's'], help='Type of application:\n\te : enabled Apps\n\td : ' + \
                                                                 'disabled Apps\n\t3 : Third party Apps\n\ts : System Apps',
                        default='3', dest='app_type')
    parser.add_argument('-D', '--dump-apks',
                        help='Dump APKs from device to APKS_DUMP_FOLDER directory', dest="apks_dump_folder")

    args = parser.parse_args()
    return args


# Status of the App
class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


def device_choice(adb_instance):
    choice = 0
    while True:
        print("List of devices:")
        devices = adb_instance.list_devices()

        if not len(devices):
            print_error("No device found")
            exit(1)

        for device in devices:
            choice = choice + 1
            print(str(choice) + " - " + device + " : " + devices[device])

        keys = list(devices)

        choice = int(input("Select device in list [ " + ''.join([str(i + 1) + " " for i in range(choice)]) + "]:"))
        if choice < 1 or choice > len(devices):
            print_error("Choose a device in the list")
            continue

        choosen_device = str(keys[choice - 1])
        if "offline" in devices[choosen_device] or "unauthorized" in devices[choosen_device]:
            print_error("You cannot use " + choosen_device + ", reason: " + devices[device])
            choice = -1
        else:
            break

    return keys[choice - 1]


def amdh():
    arguments = args_parse()

    if arguments.adb_path:
        adb_path = arguments.adb_path

    dump_apks = False
    apks_dump_folder = ""
    if arguments.apks_dump_folder:
        dump_apks = True
        apks_dump_folder = arguments.apks_dump_folder

    adb_instance = ADB(adb_path)
    device_id = device_choice(adb_instance)
    adb_instance = ADB(adb_path, device_id)
    settings_check = None

    packages = []
    if arguments.app_type:
        packages = adb_instance.list_installed_packages(arguments.app_type)

    report_apps = {}
    for package in packages:
        dumpsys_out = adb_instance.dumpsys(["package", package])
        perm_list = adb_instance.get_req_perms_dumpsys_package(dumpsys_out)
        app = App(adb_instance, package, dump_apks, apks_dump_folder, perm_list)
        perms, dangerous_perms = app.check_apps()
        print("")
        if dangerous_perms.items():
            print_warning_header("Package " + package + " have some dangerous permissions: ")
            for perm, desc in dangerous_perms.items():
                print_warning("\t " + perm + " : ")
                print_warning("\t\t" + desc)
            report_apps[package] = {"permissions": perms, "dangerous_perms": dangerous_perms}
            print("")
            print("************************************************************************")
        else:
            print_info("Package " + package + " have no dangerous permissions")
            print("")
            print("************************************************************************")

    if arguments.H:
        settings_check = Settings(settings_file, adb_instance, True)
    else:
        settings_check = Settings(settings_file, adb_instance)

    settings_check.check()


if __name__ == "__main__":
    amdh()
