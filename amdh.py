from enum import Enum
from sys import platform
import argparse
import sys
import os
import json
from shutil import which
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from datetime import datetime
from core.settings import Settings
from core.adb import ADB
from utils.out import *
from config.main import *
from core.snapshot import Snapshot
from core.app import App


# Status of the App
class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


# variables
out = Out("Linux")
devices = []
dump_apks = False
apks_dump_folder = "out"
scan_settings = False
scan_applications = False
harden = False
list_apps = False
list_processes = False
snapshot = False
snapshot_dir = "snap_out"
cmp_snap = False
snapshot_report = "snap_repot.json"
backup = False
restore_snap = False
snap_to_restore = snapshot_report
app_type = Status.THIRD_PARTY
revoke = False
rm_admin_recv = False
lock = threading.Lock()
adb_path = ""
output_dir = "out"


def args_parse(print_help=False):
    parser = argparse.ArgumentParser(description='Android Mobile Device Hardening\n',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-d', '--devices',
                        help='list of devices separated by comma or "ALL" for all connected devices',
                        dest='devices')

    parser.add_argument('-sS',
                        help='Scan the system settings',
                        action='store_true')

    parser.add_argument('-sA',
                        help='Scan the installed applications',
                        action='store_true')

    parser.add_argument('-H',
                        help='Harden system settings /!\ Developer Options and ADB will be disabled /!\ ',
                        action='store_true')

    parser.add_argument('-a', '--adb-path',
                        help='Path to ADB binary',
                        default='adb',
                        dest='adb_path')

    parser.add_argument('-t',
                        choices=['e', 'd', '3', 's'],
                        help='Type of applications:\n\te: enabled Apps\n\td: disabled Apps\n\t3: Third party Apps'
                             '\n\ts: System Apps',
                        default='3',
                        dest='app_type')

    parser.add_argument('-D', '--dump-apks',
                        help='Dump APKs from device to APKS_DUMP_FOLDER directory',
                        dest='apks_dump_folder')

    parser.add_argument('-rar',
                        help='Remove admin receivers: Remove all admin receivers if the app is not a system App\n'
                             'Scan application option "-sA" is required',
                        action='store_true')

    parser.add_argument('-R',
                        help='For each app revoke all dangerous permissions\n'
                             'Scan application option "-sA" is required',
                        action='store_true')

    parser.add_argument('-l',
                        help='List numbered applications to disable, uninstall or analyze\n',
                        action='store_true')

    parser.add_argument('-P',
                        help='List current users processes',
                        action='store_true')

    parser.add_argument('-S', '--snapshot',
                        help='Snapshot the current state of the phone to a json file and backup applications into '
                             'SNAPSHOT_DIR',
                        dest='snapshot_dir')

    parser.add_argument('-cS', '--cmp-snapshot',
                        help='Compare SNAPSHOT_REPORT with the current phone state',
                        dest='snapshot_report')

    parser.add_argument('-rS', '--restore-snapshot',
                        help='Restore SNAPSHOT_TO_RESTORE',
                        dest='snapshot_to_restore')

    parser.add_argument('-o', '--output-dir',
                        help='Output directory for reports and logs. Default: out',
                        dest='output_dir')

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


def set_output_std():
    global out
    if platform == "linux" or platform == "linux2":
        out = Out("Linux")
    elif platform == "darwin":
        out = Out("Darwin")
    elif platform == "win32":
        out = Out("Windows")


def init_vars(arguments):
    set_output_std()

    global output_dir
    if arguments.output_dir:
        output_dir = arguments.output_dir
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    else:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

    global adb_path
    if arguments.adb_path:
        adb_path = arguments.adb_path
    else:
        if platform == "linux" or platform == "linux2" or platform == "Darwin":
            if which("adb") is None and not os.path.isfile(ADB_BINARY):
                out.print_error("adb not found please use '-a' to specify the path")
                args_parse(True)
                sys.exit(1)
        else:  # Windows
            if which("adb") is None and not os.path.isfile(ADB_WINDOWS_PATH):
                out.print_error("adb not found please use '-a' to specify the path")
                sys.exit(1)

    global devices
    if arguments.devices:
        if ',' in arguments.devices:
            devices = arguments.devices.split(',')
        elif arguments.devices == "ALL":
            devices = ADB(adb_path).list_devices()
        else:
            devices.append(arguments.devices)

    elif not ADB(adb_path).list_devices():
        out.print_error("No device found")
        sys.exit(1)

    # Related to APKs dump
    global dump_apks
    global apks_dump_folder

    if arguments.apks_dump_folder:
        dump_apks = True
        apks_dump_folder = arguments.apks_dump_folder

    # Related to scan
    #   scan settings
    global scan_settings
    scan_settings = False
    if arguments.sS:
        scan_settings = True

    #   scan applications
    global scan_applications
    scan_applications = False
    if arguments.sA:
        scan_applications = True

    # Hardening param
    global harden
    harden = False
    if arguments.H:
        harden = True

    # list applications param
    global list_apps
    list_apps = False
    if arguments.l:
        list_apps = True

    # list running users processes
    global list_processes
    list_processes = False
    if arguments.P:
        list_processes = True

    # Related to snapshot
    global snapshot
    snapshot = False
    global snapshot_dir
    snapshot_dir = ""
    if arguments.snapshot_dir:
        snapshot = True
        snapshot_dir = arguments.snapshot_dir

    # Snapshot comparison
    global cmp_snap
    cmp_snap = False
    global snapshot_report
    snapshot_report = ""
    global backup
    if arguments.snapshot_report:
        cmp_snap = True
        backup = False
        snapshot_report = arguments.snapshot_report

    # Snapshot restore
    global restore_snap
    global snap_to_restore
    restore_snap = False
    snap_to_restore = ""
    if arguments.snapshot_to_restore:
        restore_snap = True
        snap_to_restore = arguments.snapshot_to_restore

    # Check if one of the operation are chosen
    if not scan_settings and not scan_applications and not dump_apks and not harden and not list_apps and \
            not list_processes and not snapshot and not cmp_snap and not restore_snap:
        out.print_error("Please choose an operation")
        args_parse(True)
        exit(1)

    global app_type
    app_type = Status.THIRD_PARTY.value
    if arguments.app_type:
        try:
            app_type = Status(arguments.app_type)
        except Exception as e:
            print("Application type invalid")

    global revoke
    revoke = False
    if arguments.R:
        revoke = True

    global rm_admin_recv
    rm_admin_recv = False
    if arguments.rar:
        rm_admin_recv = True

    if app_type.value == 'e':
        out.print_info("Scanning system apps may takes a while ...")


def process_settings(adb_instance, device_id):
    if harden:
        settings_check = Settings(SETTINGS_FILE, adb_instance, True, out)
    else:
        settings_check = Settings(SETTINGS_FILE, adb_instance, out=out)

    if scan_settings:

        with open(f"{output_dir}/{device_id}_report_settings.json", 'w') as fp:
            json.dump(settings_check.check(), fp, indent=4)

        out.print_info("Report generated: %s_report_settings.json" % device_id)


def process_applications(adb_instance, device_id):
    packages = []
    report_apps = {}

    if app_type:
        packages = adb_instance.list_installed_packages(app_type.value)

    for package in packages:
        if not list_apps:
            out.print_info(package)

        report_apps[package] = dict()

        app = App(adb_instance, package, scan_applications, dump_apks, apks_dump_folder)
        perms, dangerous_perms, is_device_admin, known_malware = app.check_app()

        if known_malware:
            out.print_error(f"{package} is known as malware")
            report_apps[package]["malware"] = True

        if scan_applications:
            if dangerous_perms and dangerous_perms.items():
                out.print_warning_header("Package {} has some dangerous permissions: ".format(package))

                for perm, desc in dangerous_perms.items():
                    out.print_warning("\t " + perm + ": ")
                    out.print_warning("\t\t" + desc)

                report_apps[package]["permissions"] = dict()
                report_apps[package]["permissions"] = {"all_permissions": list(perms.keys()),
                                                       "dangerous_perms": dangerous_perms}
                report_apps[package]["is_device_admin"] = is_device_admin

            else:
                out.print_info("Package {} has no dangerous permissions".format(package))

            if is_device_admin:
                message = f"/!\ \t {package} is device admin \t /!\ "
                padding = len(message)
                out.print_warning("-" * padding)
                out.print_warning(message)
                out.print_warning("-" * padding)

                report_apps[package] = {"device_admin": is_device_admin}

                if rm_admin_recv:
                    removed, dpm = app.remove_device_admin_for_app()
                    if removed:
                        report_apps[package] = {"device_admin_revoked": True}
                        out.print_info("Device admin receivers for {} removed\n".format(app.package_name))
                    else:
                        out.print_error("An error occured while removing the device admin " + dpm + " .")

            # Revoke all Dangerous permissions
            if revoke and app.dangerous_perms:

                succeeded = app.revoke_dangerous_perms()

                if succeeded:
                    report_apps[package]["revoked_dangerous_pemissions"] = "succeeded"
                    out.print_info("Dangerous permissions revoked\n")
                else:
                    out.print_error(f"An error occured while revoking"
                                    "permission {perm} to package {app.package_name}")

            elif revoke and not app.dangerous_perms:
                out.print_info("No dangerous permissions granted for this package\n")

            if app.malware_confidence > 0 or app.score < 0:
                out.print_high_warning("----------------------------MALWARE SCAN--------------------------------")
                out.print_high_warning("The application uses some permissions used also by malware")
                if app.malware_confidence > 0:
                    out.print_high_warning(str(app.malware_confidence) + " permissions combinations used also by "
                                                                         "malware")

            if app.score < 0:
                out.print_high_warning("The application uses frequent malware permissions ")

    if scan_applications:
        with open(f"{output_dir}/{device_id}_report_apps.json", 'w') as fp:
            json.dump(report_apps, fp, indent=4)

        out.print_info("Report generated: %s_report_apps.json" % device_id)

    return report_apps


def process_snapshot(adb_instance, device_id):
    with lock:
        input("Unlock device %s and press ENTER key to continue" % device_id)

        # set stay_awake to 1
    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "1", "i")

    out.print_info("Starting snapshot")
    if not os.path.isdir(snapshot_dir):
        os.makedirs(snapshot_dir)

    snapshot_path = snapshot_dir + "/" + device_id + "_" + datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    if not os.path.isdir(snapshot_path):
        os.makedirs(snapshot_path)

    if app_type:
        snapshot_obj = Snapshot(adb_instance, app_type.value, out_dir=snapshot_path)
    else:
        snapshot_obj = Snapshot(adb_instance, out_dir=snapshot_path)
    report = snapshot_obj.get_report()

    with open(snapshot_path + "/snapshot.json", 'w') as fp:
        json.dump(report, fp, indent=4)

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "0", "i")
    out.print_info("Snapshot finished")


def process_snapshot_cmp(adb_instance):
    cmp_report = Snapshot(adb_instance, snapshot_file=snapshot_report, backup=backup).snapshot_compare()

    out.print_info("Installed Apps after snapshot was taken")
    out.print(json.dumps(cmp_report["apps"]["new_installed_apps"], indent=4))
    out.print_info("Apps exists in snapshot")
    print(json.dumps(cmp_report["apps"]["apps_exist_in_snap"], indent=4))
    out.print_info("Uninstalled after snapshot was taken")
    print(json.dumps(cmp_report["apps"]["uninstalled_apps"], indent=4))

    out.print_info("Changed settings after snapshot was taken")
    print(json.dumps(cmp_report["settings"], indent=4))


def process_snapshot_restore(adb_instance):
    input("Unlock your phone and press ENTER key to continue")

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "1", "i")
    out.print_info("Starting restore")
    restore_report = Snapshot(adb_instance, snapshot_file=snap_to_restore, backup=False).snapshot_restore()

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "0", "i")
    out.print_info("Restore finished")

    out.print_info("Restore report")
    print(json.dumps(restore_report, indent=4))


def interactive_list_processes(adb_instance, device_id):
    lock.acquire()
    process_choice_list = []
    current_processes = adb_instance.list_backgroud_apps().split("\n")
    print("Current running user processes on the device %s" % device_id)

    for i in range(0, len(current_processes) - 1):
        print("   {}- {}".format(i + 1, current_processes[i]))

    print("")
    choice = input("Select id(s) of process(es) to kill (separated by comma ','): ")
    chosen_processes = choice.replace(" ", "").split(",")
    for c in chosen_processes:
        if c.isdigit() and (0 < int(c) < len(current_processes) + 1):
            process_choice_list = process_choice_list + [c]
            lock.release()
        else:
            print("[X] ERROR: process does not exist")
            print("Exiting device %s" % device_id)
            lock.release()
            return

    for proc in process_choice_list:
        adb_instance.force_stop_app(current_processes[int(proc) - 1])


def interactive_list_apps(adb_instance, device_id):
    lock.acquire()
    if app_type:
        packages = adb_instance.list_installed_packages(app_type.value)
        if app_type.value == 'e':
            print("Uninstalling or disabling system Apps can break your system")

    print("List of installed packages on device %s: " % device_id)
    nbr_listed_apps = 0
    apps_choice_list = []
    for package in packages:
        if nbr_listed_apps < LIST_APPS_MAX_PRINT and \
                packages.index(package) < (len(packages) - 1):
            print("\t[" + str(packages.index(package) + 1) + "] " + package)
            nbr_listed_apps = nbr_listed_apps + 1
        else:
            choice = ''
            if packages.index(package) == (len(packages) - 1):
                print("\t[" + str(packages.index(package) + 1) + "] " + package)
            while True:
                choice = input("Select application(s) (separated by comma ','), 'c' to continue"
                               " listing apps and 'A' for actions menu: ")
                if choice == 'c':
                    nbr_listed_apps = 1
                    break

                if choice == 'A':
                    break

                else:
                    chosen_apps = choice.replace(" ", "").split(",")
                    for c in chosen_apps:
                        if c.isdigit() and (0 < int(c) < len(packages) + 1):
                            apps_choice_list = apps_choice_list + [c]

                        else:
                            print(f"option {c} does not exist")

            if choice == 'A':
                break

    if not len(apps_choice_list):
        print("No application selected")
        return

    while True:
        print("choose an action")
        print("\td: disable selected apps")
        print("\tu: uninstall selected apps")
        print("\ts: static analysis")
        print("\te: exit")
        print("")

        action = input("Action: ")
        action = action.replace(" ", "")

        if action == 'd' or action == 'u' or action == 's' or action == 'e':
            lock.release()
            break
        else:
            print("ERROR: Invalid action")
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

        elif action == 's':
            app = App(adb_instance, packages[int(id_app) - 1], dump_apk=True, out_dir=apks_dump_folder)
            out.print_info(f"Package {packages[int(id_app) - 1]}")
            package_info = app.static_analysis()
            print(package_info)
            out.print_info("\tMalware identification")

            for key, value in package_info["detected_malware"].items():
                if value > 0:
                    out.print_error("\t\t " + key + ": " + str(value) + " positives tests")
                else:
                    out.print_info("\t\t " + key + ": " + str(value) + " positive test")

            if package_info and package_info["packed_file"] and \
                    package_info["packed_file"][packages[int(id_app) - 1]].keys():

                out.print_info("\tPacked files")
                out.print_error(f"The package {packages[int(id_app) - 1]} has another Application (APK) inside")

                for file in package_info["packed_file"][packages[int(id_app) - 1]]:
                    for perm in package_info["packed_file"][packages[int(id_app) - 1]][file]:
                        out.print_error("\tDangerous Permission: " + perm)

        elif action == 'e':
            break


def process(device_id):
    global out
    adb_instance = ADB(adb_path, device_id)
    out = Out(filename=f"{output_dir}/{device_id}.log")

    if adb_instance.check_pending_update():
        lock.acquire()
        out.print_warning("%s: The system has a pending updates!" % device_id)
        lock.release()

    if scan_applications or dump_apks or list_apps:
        process_applications(adb_instance, device_id)

    if scan_settings:
        process_settings(adb_instance, device_id)

    if list_apps:
        interactive_list_apps(adb_instance, device_id)

    if list_processes:
        interactive_list_processes(adb_instance, device_id)

    if snapshot:
        process_snapshot(adb_instance, device_id)

    if restore_snap:
        set_output_std()
        process_snapshot_restore(adb_instance)

    if cmp_snap:
        set_output_std()
        process_snapshot_cmp(adb_instance)


def check_device_up():
    connected_devices = ADB(adb_path).list_devices()
    for device in devices:
        if device not in connected_devices.keys():
            out.print_error(f"{device} not found")
            sys.exit(1)

        device_status = connected_devices[device]
        if "offline" in device_status or "unauthorized" in device_status \
                or "no permissions" in device_status:
            out.print_error(f"The device {device} cannot be used. Reason: {connected_devices[device]}")
            sys.exit(1)


def amdh():
    arguments = args_parse()
    connected_devices = ADB(ADB_BINARY).list_devices()
    init_vars(arguments)

    if not devices:
        if len(connected_devices) == 0:
            out.print_error("No device founded")
            sys.exit(1)
        elif len(connected_devices) > 1:
            out.print_error("Please use -d to specify the devices to use")
            out.print_info("Current connected devices")
            for device in connected_devices:
                print(device)
            sys.exit(1)
        else:
            devices.append(list(connected_devices.keys())[0])

    check_device_up()

    out.print_info("Start ...")

    with ThreadPoolExecutor(max_workers=len(devices)) as executor:
        results = {executor.submit(process, device): device for device in devices}
        as_completed(results)

    set_output_std()
    out.print_info("Finished")


if __name__ == "__main__":
    amdh()
