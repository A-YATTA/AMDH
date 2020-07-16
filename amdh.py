from core.adb import ADB
from utils.out import *
from core.settings import Settings
from enum import Enum
from sys import platform
import argparse
from core.app import App
from argparse import RawTextHelpFormatter
import time
import sys
import os

adb_path = "/usr/bin/adba"
settings_file = "config/settings.json"
out = Out("Linux")
adb_windows_path = "%LOCALAPPDATA%/Android/Sdk/platform-tools/adb"


def args_parse(print_help=False):
    parser = argparse.ArgumentParser(description='Android Mobile Device Hardening\nBy default the script will scan ' + \
                                                 'the Android system and Apps without any modification',
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument('-s', help='scan the settings and applications installed', action='store_true')
    parser.add_argument('-H', help='Harden system settings /!\ Developer Options and ADB will be disabled /!\ ',
                        action='store_true')
    parser.add_argument('-a', '--adb-path', help='Path to ADB binary', default='/usr/bin/adb', dest='adb_path')
    """parser.add_argument('-d', '--device', help='Device id (check "adb list-devices"). If none the script will list ' 
                                               'current connected devices', dest="device_id")"""
    parser.add_argument('-t', choices=['e', 'd', '3', 's'], help='Type of applications:\n\te : enabled Apps\n\td : '
                                                                 'disabled Apps\n\t3 : Third party Apps\n\ts : System '
                                                                 'Apps',
                        default='3', dest='app_type')
    parser.add_argument('-D', '--dump-apks', help='Dump APKs from device to APKS_DUMP_FOLDER directory',
                        dest='apks_dump_folder')
    parser.add_argument('-rar',
                        help='remove admin receivers: Remove all admin receivers if the app is not a system App\n'
                             'Scan option is required',
                        action='store_true')
    parser.add_argument('-R',
                        help='For each app revoke all dangerous permissions\n'
                             'Scan option is required',
                        action='store_true')

    args = parser.parse_args()

    if (args.rar or args.R) and not args.s:
        out.print_error("Option depend on -s")
        sys.exit(1)

    if print_help:
        parser.print_help(sys.stderr)
        return

    return args


# Status of the App
class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


def device_choice(adb_instance):
    choice = 0
    keys = list()
    while True:
        out.print_info("List of devices:")
        devices = adb_instance.list_devices()

        if not len(devices):
            out.print_error("No device found")
            sys.exit(1)
        elif len(devices) == 1:
            out.print_info("The device " + list(devices.keys())[0] + " will be used.\n")
            return list(devices.keys())[0]

        for device in devices:
            choice = choice + 1
            print(str(choice) + " - " + device + " : " + devices[device])

        keys = list(devices)

        choice = int(input("Select device in list [ " + ''.join([str(i + 1) + " " for i in range(choice)]) + "]:"))
        if choice < 1 or choice > len(devices):
            out.print_error("Choose a device in the list")
            continue

        chosen_device = str(keys[choice - 1])
        if "offline" in devices[chosen_device] or "unauthorized" in devices[chosen_device]:
            out.print_error("You cannot use " + chosen_device + ", reason: " + devices[device])
            choice = -1
        else:
            break

    return keys[choice - 1]


def amdh():
    global out
    global adb_path

    if platform == "linux" or platform == "linux2":
        out = Out("Linux")
    elif platform == "darwin":
        out = Out("Darwin")
    elif platform == "win32":
        out = Out("Windows")

    arguments = args_parse()

    # ADB binary path
    if arguments.adb_path:
        adb_path = arguments.adb_path
    else:
        if platform == "linux" or platform == "linux2" or platform == "Darwin":
            if not os.path.isfile(adb_path):
                out.print_error("adb not found please use '-d' to specify the path")
                args_parse(True)
                sys.exit(1)
        else:  # Windows
            if not os.path.isfile(adb_windows_path):
                out.print_error("adb not found please use '-d' to specify the path")
                sys.exit(1)

    # Related to APKs dump
    dump_apks = False
    apks_dump_folder = ""
    if arguments.apks_dump_folder:
        dump_apks = True
        apks_dump_folder = arguments.apks_dump_folder

    # Related to scan
    scan = False
    if arguments.s:
        scan = True

    # Hardening param
    harden = False
    if arguments.H:
        harden = True

    # Check if one of the operation are chosen
    if not scan and not dump_apks and not harden:
        out.print_error("Please choose an operation")
        args_parse(True)
        exit(1)

    adb_instance = ADB(adb_path)
    device_id = device_choice(adb_instance)
    adb_instance = ADB(adb_path, device_id)
    settings_check = None

    packages = []
    if arguments.app_type:
        packages = adb_instance.list_installed_packages(arguments.app_type)

    report_apps = {}
    for package in packages:
        out.print_info(package)
        dumpsys_out = adb_instance.dumpsys(["package", package])
        perm_list = adb_instance.get_req_perms_dumpsys_package(dumpsys_out)
        app = App(adb_instance, package, scan, dump_apks, apks_dump_folder, perm_list)
        perms, dangerous_perms, is_device_owner, malware_confidence_detect = app.check_app()
        print("")
        if scan:

            if dangerous_perms.items():
                out.print_warning_header("Package " + package + " has some dangerous permissions: ")
                for perm, desc in dangerous_perms.items():
                    out.print_warning("\t " + perm + " : ")
                    out.print_warning("\t\t" + desc)
                report_apps[package] = {"permissions": perms, "dangerous_perms": dangerous_perms}

            else:
                out.print_info("Package " + package + " has no dangerous permissions")

            if is_device_owner:
                message = "/!\ \t" + package + " is device owner\t/!\ "
                padding = len(message)
                out.print_warning("-" * padding)
                out.print_warning(message)
                out.print_warning("-" * padding)

                if arguments.rar:
                    removed, dpm = app.remove_device_admin_for_app()
                    if removed:
                        out.print_info("Device admin receivers for " + app.package_name + " removed\n")
                    else:
                        out.print_error("An error occured while removing the device admin " + dpm + " .")

            # Revoke all Dangerous permissions
            if arguments.R and app.dangerous_perms:
                successed = app.revoke_dangerous_perms()
                if successed:
                    out.print_info("Dangerous permissions revoked\n")
                else:
                    out.print_error("An error occured while revoking permission " + perm + " to package " + app.package_name)
            elif arguments.R and not app.dangerous_perms:
                out.print_info("No dangerous permissions granted for this package\n")

            if malware_confidence_detect > 0:
                out.print_high_warning("----------------------------MALWARE SCAN--------------------------------")
                out.print_high_warning("The application uses some malwares permissions ")
                out.print_high_warning(str(malware_confidence_detect) + " combinations ")
                out.print_high_warning("------------------------------------------------------------------------")

        print("************************************************************************")
        time.sleep(0.5)

    if arguments.H:
        settings_check = Settings(settings_file, adb_instance, True, out=out)
    else:
        settings_check = Settings(settings_file, adb_instance, out=out)

    if arguments.s:
        settings_check.check()


if __name__ == "__main__":
    amdh()
