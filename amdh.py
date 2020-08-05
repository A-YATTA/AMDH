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

adb_path = "/usr/bin/adb"
settings_file = "config/settings.json"
out = Out("Linux")
adb_windows_path = "%LOCALAPPDATA%/Android/Sdk/platform-tools/adb"

LIST_APPS_MAX_PRINT = 15


def args_parse(print_help=False):
    parser = argparse.ArgumentParser(description='Android Mobile Device Hardening\nBy default the script will scan '
                                                 'the Android system and Apps without any modification',
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument('-sS', help='scan the system settings', action='store_true')
    parser.add_argument('-sA', help='scan the installed applications', action='store_true')
    parser.add_argument('-H', help='Harden system settings /!\ Developer Options and ADB will be disabled /!\ ',
                        action='store_true')
    parser.add_argument('-a', '--adb-path', help='Path to ADB binary', default='/usr/bin/adb', dest='adb_path')
    parser.add_argument('-t', choices=['e', 'd', '3', 's'], help='Type of applications:\n\te : enabled Apps\n\td : '
                                                                 'disabled Apps\n\t3 : Third party Apps\n\ts : System '
                                                                 'Apps',
                        default='3', dest='app_type')

    parser.add_argument('-D', '--dump-apks', help='Dump APKs from device to APKS_DUMP_FOLDER directory',
                        dest='apks_dump_folder')
    parser.add_argument('-rar',
                        help='remove admin receivers: Remove all admin receivers if the app is not a system App\n'
                             'Scan application option "-sA" is required',
                        action='store_true')
    parser.add_argument('-R',
                        help='For each app revoke all dangerous permissions\n'
                             'Scan application option "-sA" is required',
                        action='store_true')

    parser.add_argument('-l',
                        help='list numbered applications to disable or uninstall\n',
                        action='store_true')

    args = parser.parse_args()

    if (args.rar or args.R) and not args.sA:
        out.print_error("Option depend on scan application '-sA' ")
        sys.exit(1)

    if args.H and not args.sS:
        out.print_error("Option depend on scan -sS")
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

        try:
            choice = int(input("Select device in list [ " + ''.join([str(i + 1) + " " for i in range(choice)]) + "]:"))
        except Exception as e:
            out.print_error("Choose a device in the list")
            choice = 0
            continue

        if choice < 1 or choice > len(devices):
            out.print_error("Choose a device in the list")
            choice = 0
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
    apks_dump_folder = "out"
    if arguments.apks_dump_folder:
        dump_apks = True
        apks_dump_folder = arguments.apks_dump_folder

    # Related to scan
    #   scan settings
    scan_settings = False
    if arguments.sS:
        scan_settings = True

    #   scan applications
    scan_applications = False
    if arguments.sA:
        scan_applications = True

    # Hardening param
    harden = False
    if arguments.H:
        harden = True

    # list applications param
    list_apps = False
    if arguments.l:
        list_apps = True

    # Check if one of the operation are chosen
    if not scan_settings and not scan_applications and not dump_apks and not harden and not list_apps:
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
    if scan_applications or dump_apks or list_apps:
        if arguments.app_type == 'e':
            out.print_info("Scanning system apps may takes a while ...")
        for package in packages:
            if not list_apps:
                out.print_info(package)

            dumpsys_out = adb_instance.dumpsys(["package", package])
            perm_list = adb_instance.get_req_perms_dumpsys_package(dumpsys_out)
            app = App(adb_instance, package, scan_applications, dump_apks, apks_dump_folder, perm_list)
            perms, dangerous_perms, is_device_owner, known_malware = app.check_app()
            if known_malware:
                out.print_error("{} is known as malware".format(package))
            if scan_applications:

                if dangerous_perms != None and dangerous_perms.items():
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
                    succeeded = app.revoke_dangerous_perms()
                    if succeeded:
                        out.print_info("Dangerous permissions revoked\n")
                    else:
                        out.print_error(
                            "An error occured while revoking permission " + perm + " to package " + app.package_name)
                elif arguments.R and not app.dangerous_perms:
                    out.print_info("No dangerous permissions granted for this package\n")

                if app.malware_confidence > 0:
                    out.print_high_warning("----------------------------MALWARE SCAN--------------------------------")
                    out.print_high_warning("The application uses some permissions used also by malwares")
                    out.print_high_warning(str(app.malware_confidence) + " permissions combinations used also by "
                                                                         "malwares")

                if app.score < 0:
                    out.print_high_warning("The application uses frequent malwares permissions ")

                print("************************************************************************")
                time.sleep(0.5)
    if list_apps:
        print("************************************************************************")
        out.print_info("List of installed packages: ")
        nbr_listed_apps = 0
        apps_choice_list = []
        for package in packages:
            if nbr_listed_apps < LIST_APPS_MAX_PRINT and packages.index(package) < (len(packages) - 1):
                out.print_info("\t[" + str(packages.index(package) + 1) + "] " + package)
                nbr_listed_apps = nbr_listed_apps + 1
            else:
                choice = ''
                if packages.index(package) == (len(packages) - 1):
                    out.print_info("\t[" + str(packages.index(package) + 1) + "] " + package)
                while True:
                    choice = input("Select application(s) (separated by comma ','), 'c' to continue listing apps and "
                                   "'A' for actions menu: ")
                    if choice == 'c':
                        nbr_listed_apps = 1
                        break

                    if choice == 'A':
                        break

                    else:
                        choosen_apps = choice.replace(" ", "").split(",")
                        for c in choosen_apps:
                            if c.isdigit() and (0 < int(c) < len(packages) + 1):
                                apps_choice_list = apps_choice_list + [c]

                            else:
                                out.print_error("option " + c + " does not exist")

                if choice == 'A':
                    break

        if arguments.app_type == 'e':
            out.print_high_warning("Uninstalling or disabling system Apps can break your system")

        action = ""
        while True:
            out.print_info("choose an action")
            out.print_info("\td: disable selected apps")
            out.print_info("\tu: uninstall selected apps")
            out.print_info("\tS: static analysis")
            out.print_info("\ts: skip")
            print("")

            action = input("Action: ")
            action = action.replace(" ", "")

            if action == 'd' or action == 'u' or action == 's' or action == 'S':
                break
            else:
                print("action " + action + " this")
                out.print_error("Invalid action")
                continue

        for id_app in apps_choice_list:
            if action == 'd':
                try:
                    adb_instance.disable_app(packages[int(id_app) - 1])
                    out.print_success(packages[int(id_app) - 1] + " disabled")
                except Exception as e:
                    out.print_error("An Error occurred while disabling " + packages[int(id_app) - 1])

            elif action == 'u':
                try:
                    adb_instance.uninstall_app(packages[int(id_app) - 1])
                    out.print_success(packages[int(id_app) - 1] + " uninstalled")
                except Exception as e:
                    out.print_error("An Error occurred while uninstalling " + packages[int(id_app) - 1])

            elif action == "S":
                #try:
                app = App(adb_instance, packages[int(id_app) - 1], dump_apk=True, out_dir=apks_dump_folder)
                out.print_info("Package {}".format(packages[int(id_app) - 1]))
                package_info = app.static_analysis()
                out.print_info("\tMalware identification")
                for key, value in package_info["detected_malwares"].items():
                    out.print_error("\t\t " + key + ": " + str(value) + " positives tests")

                out.print_info("\tPacked files")
                if package_info and package_info["packed_file"][packages[int(id_app) - 1]].keys() :
                    out.print_error("The package {} has another Application (APK) inside".format(packages[int(id_app) - 1]))

                    for file in package_info["packed_file"][packages[int(id_app) - 1]]:
                        for perm in package_info["packed_file"][packages[int(id_app) - 1]][file]:
                            out.print_error("\tDangerous Permission: " + perm)

            elif action == 's':
                break

    if harden:
        settings_check = Settings(settings_file, adb_instance, True, out=out)
    else:
        settings_check = Settings(settings_file, adb_instance, out=out)

    if scan_settings:
        settings_check.check()


if __name__ == "__main__":
    amdh()
