import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core.settings import Settings
from core.snapshot import Snapshot
from core.app import App
from utils.main_settings import *

main_settings = MainSettings()


def process_settings(adb_instance, device_id=""):
    if main_settings.harden:
        settings_check = Settings(SETTINGS_FILE, adb_instance, True, out=main_settings.out[device_id])
    else:
        settings_check = Settings(SETTINGS_FILE, adb_instance, out=main_settings.out[device_id])

    if main_settings.scan_settings:
        with open(f"{main_settings.output_dir}/{device_id}_report_settings.json", 'w') as fp:
            json.dump(settings_check.check(), fp, indent=4)

        main_settings.out["std"].print_info("Report generated: %s_report_settings.json" % device_id)


def process_applications(adb_instance, device_id=""):
    packages = []
    report_apps = {}

    if main_settings.app_type:
        packages = adb_instance.list_installed_packages(main_settings.app_type.value)
    try:
        for package in packages:
            if not main_settings.list_apps:
                main_settings.out[device_id].print_info(package)

            report_apps[package] = dict()
            app = App(adb_instance, package, main_settings.scan_applications, main_settings.dump_apks,
                      main_settings.apks_dump_folder + "/" + device_id)

            perms, dangerous_perms, is_device_admin, known_malware = app.check_app()

            if known_malware:
                main_settings.out[device_id].print_error(f"{package} is known as malware")
                report_apps[package]["malware"] = True

            if main_settings.scan_applications:
                if len(dangerous_perms) and dangerous_perms.items():
                    main_settings.out[device_id].print_warning_header(
                        "Package {} has some dangerous permissions: ".format(package))

                    for perm, desc in dangerous_perms.items():
                        main_settings.out[device_id].print_warning("\t " + perm + ": ")
                        main_settings.out[device_id].print_warning("\t\t" + desc)

                    report_apps[package]["permissions"] = dict()
                    report_apps[package]["permissions"] = {"all_permissions": list(perms.keys()),
                                                           "dangerous_perms": dangerous_perms}
                    report_apps[package]["is_device_admin"] = is_device_admin

                else:
                    main_settings.out[device_id].print_info("Package {} has no dangerous permissions".format(package))

                if is_device_admin:
                    message = f"/!\ \t {package} is device admin \t /!\ "
                    padding = len(message)
                    main_settings.out[device_id].print_warning("-" * padding)
                    main_settings.out[device_id].print_warning(message)
                    main_settings.out[device_id].print_warning("-" * padding)

                    report_apps[package] = {"device_admin": is_device_admin}

                    if main_settings.rm_admin_recv:
                        removed, dpm = app.remove_device_admin_for_app()
                        if removed:
                            main_settings.out[device_id][package] = {"device_admin_revoked": True}
                            main_settings.out[device_id].print_info(
                                "Device admin receivers for {} removed\n".format(app.package_name))
                        else:
                            main_settings.out[device_id].print_error(
                                "An error occured while removing the device admin " + dpm + " .")

                # Revoke all Dangerous permissions
                if main_settings.revoke and app.dangerous_perms:
                    succeeded = app.revoke_dangerous_perms()

                    if succeeded:
                        report_apps[package]["revoked_dangerous_pemissions"] = "succeeded"
                        main_settings.out[device_id].print_info("Dangerous permissions revoked\n")
                    else:
                        main_settings.out[device_id].print_error(f"An error occured while revoking"
                                                                 "permission {perm} to package {app.package_name}")

                elif main_settings.revoke and not app.dangerous_perms:
                    main_settings.out[device_id].print_info("No dangerous permissions granted for this package\n")

                main_settings.out[device_id].print_info(
                    "----------------------------MALWARE SCAN--------------------------------")
                if app.score > 0:
                    main_settings.out[device_id].print_high_warning(
                        f'The application uses some permissions used also by malware. Percentage : {app.score}%')
                if app.malware_combination > 0:
                    main_settings.out[device_id].print_high_warning(f'{str(app.malware_combination)} permissions '
                                                                    f'combinations used also by malware')
                if app.malware_only_perms > 0:
                    main_settings.out[device_id].print_high_warning(f'{str(app.malware_only_perms)} permissions '
                                                                    f' used by malware only.')
                main_settings.out[device_id].print_info(
                    "-----------------------------------------------------------------------------\n")
    except Exception as e:
        print(e)

    if main_settings.scan_applications:
        with open(f"{main_settings.output_dir}/{device_id}_report_apps.json", 'w') as fp:
            json.dump(report_apps, fp, indent=4)
        main_settings.out["std"].print_info("Report generated: %s_report_apps.json" % device_id)

    return report_apps


def process_snapshot(adb_instance, device_id):
    main_settings.lock.acquire()
    input("Unlock the device %s and press ENTER key to continue" % device_id)
    # TODO: Check if device is unlocked
    # set stay_awake to 1
    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "1", "i")

    main_settings.out["std"].print_info(f"Starting snapshot on {device_id}")

    if not os.path.isdir(main_settings.snapshot_dir):
        os.makedirs(main_settings.snapshot_dir)

    snapshot_path = main_settings.snapshot_dir + "/" + device_id + "_" + datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    if not os.path.isdir(snapshot_path):
        os.makedirs(snapshot_path)

    if main_settings.app_type:
        snapshot = Snapshot(adb_instance, main_settings.app_type.value, out_dir=snapshot_path)
    else:
        snapshot = Snapshot(adb_instance, out_dir=snapshot_path)
    report = snapshot.get_report()

    with open(snapshot_path + "/snapshot.json", 'w') as fp:
        json.dump(report, fp, indent=4)

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "0", "i")
    main_settings.out["std"].print_info(f"Snapshot {device_id} finished")
    main_settings.lock.release()


def process_snapshot_cmp(adb_instance):
    cmp_report = Snapshot(adb_instance, snapshot_file=main_settings.snapshot_report,
                          backup=main_settings.backup).snapshot_compare()

    main_settings.out["std"].print_info("Installed Apps after snapshot was taken")
    main_settings.out["std"].print(json.dumps(cmp_report["apps"]["new_installed_apps"], indent=4))
    main_settings.out["std"].print_info("Apps exists in snapshot")
    print(json.dumps(cmp_report["apps"]["apps_exist_in_snap"], indent=4))
    main_settings.out["std"].print_info("Uninstalled after snapshot was taken")
    print(json.dumps(cmp_report["apps"]["uninstalled_apps"], indent=4))

    main_settings.out["std"].print_info("Changed settings after snapshot was taken")
    print(json.dumps(cmp_report["settings"], indent=4))


def process_snapshot_restore(adb_instance):
    input("Unlock your phone and press ENTER key to continue")

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "1", "i")
    main_settings.out["std"].print_info("Starting restore")
    restore_report = Snapshot(adb_instance, snapshot_file=main_settings.snap_to_restore,
                              backup=False).snapshot_restore()

    adb_instance.content_insert_settings("global", "stay_on_while_plugged_in", "0", "i")
    main_settings.out["std"].print_info("Restore finished")

    main_settings.out["std"].print_info("Restore report")
    print(json.dumps(restore_report, indent=4))


def interactive_list_processes(adb_instance, device_id):
    main_settings.lock.acquire()
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
            main_settings.lock.release()
        else:
            print("[X] ERROR: process does not exist")
            print("Exiting device %s" % device_id)
            main_settings.lock.release()
            return

    for proc in process_choice_list:
        adb_instance.force_stop_app(current_processes[int(proc) - 1])


def interactive_list_apps(adb_instance, device_id):
    main_settings.lock.acquire()
    if main_settings.app_type:
        packages = adb_instance.list_installed_packages(main_settings.app_type.value)
        if main_settings.app_type.value == 'e':
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
        main_settings.lock.release()
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

        if action == 'd' or action == 'u' or action == 'e':
            break
        elif action == 's':
            break
        else:
            print("ERROR: Invalid action")
            continue

    for id_app in apps_choice_list:
        if action == 'd':
            try:
                adb_instance.disable_app(packages[int(id_app) - 1])
                main_settings.out["std"].print_success(packages[int(id_app) - 1] + " disabled")

            except Exception as e:
                main_settings.out["std"].print_error("An Error occurred while disabling " + packages[int(id_app) - 1])

        elif action == 'u':
            try:
                adb_instance.uninstall_app(packages[int(id_app) - 1])
                main_settings.out["std"].print_success(packages[int(id_app) - 1] + " uninstalled")

            except Exception as e:
                main_settings.out["std"].print_error(
                    "An Error occurred while uninstalling " + packages[int(id_app) - 1])

        elif action == 's':
            # TO-DO: Do analysis in other thread and log in file/DB
            app = App(adb_instance, packages[int(id_app) - 1], dump_apk=True, out_dir=main_settings.apks_dump_folder)
            main_settings.out["std"].print_info(f"Package {packages[int(id_app) - 1]}")
            package_info = app.static_analysis()
            print(package_info)
            main_settings.out["std"].print_info("\tMalware identification")

            for key, value in package_info["detected_malware"].items():
                if value > 0:
                    main_settings.out["std"].print_error("\t\t " + key + ": " + str(value) + " positives tests")
                else:
                    main_settings.out["std"].print_info("\t\t " + key + ": " + str(value) + " positive test")

            if package_info and package_info["packed_file"] and \
                    package_info["packed_file"][packages[int(id_app) - 1]].keys():

                main_settings.out["std"].print_info("\tPacked files")
                main_settings.out["std"].print_error(
                    f"The package {packages[int(id_app) - 1]} has another Application (APK) inside")

                for file in package_info["packed_file"][packages[int(id_app) - 1]]:
                    for perm in package_info["packed_file"][packages[int(id_app) - 1]][file]:
                        main_settings.out["std"].print_error("\tDangerous Permission: " + perm)
        elif action == 'e':
            break

    main_settings.lock.release()


def process(device_id):
    global main_settings

    result = {device_id: {}}

    adb_instance = ADB(main_settings.adb_path, device_id)

    main_settings.lock.acquire()
    main_settings.out[device_id] = Out(filename=f"{main_settings.output_dir}/{device_id}.log")
    main_settings.lock.release()

    if adb_instance.check_pending_update():
        main_settings.out["std"].print_warning("%s: The system has a pending updates!" % device_id)
        main_settings.out[device_id].print_warning("%s: The system has a pending updates!" % device_id)

    if main_settings.scan_applications or main_settings.dump_apks or main_settings.list_apps:
        result[device_id]['apps'] = process_applications(adb_instance, device_id)

    if main_settings.scan_settings:
        process_settings(adb_instance, device_id)

    if main_settings.list_apps:
        interactive_list_apps(adb_instance, device_id)

    if main_settings.list_processes:
        interactive_list_processes(adb_instance, device_id)

    if main_settings.snapshot:
        process_snapshot(adb_instance, device_id)

    if main_settings.restore_snap:
        main_settings.set_output_std()
        process_snapshot_restore(adb_instance)

    if main_settings.cmp_snap:
        main_settings.set_output_std()
        process_snapshot_cmp(adb_instance)

    return result


def check_device_up(devices):
    global main_settings
    connected_devices = ADB(main_settings.adb_path).list_devices()
    for device in devices:
        if device not in connected_devices.keys():
            main_settings.out["std"].print_error(f"{device} not found")
            sys.exit(1)

        device_status = connected_devices[device]
        if "offline" in device_status or "unauthorized" in device_status \
                or "no permissions" in device_status:
            main_settings.out["std"].print_error(
                f"The device {device} cannot be used. Reason: {connected_devices[device]}")
            sys.exit(1)


def initializer(args):
    global main_settings
    main_settings.arguments = args
    main_settings.init_vars()


def amdh():
    global main_settings
    main_settings.args_parse()
    main_settings.init_vars()

    connected_devices = ADB(ADB_BINARY).list_devices()

    if len(main_settings.devices) == 0 or not main_settings.devices:
        if len(connected_devices) == 0:
            main_settings.out["std"].print_error("No device found")
            sys.exit(1)
        elif len(connected_devices) > 1:
            main_settings.out["std"].print_error("Please use -d to specify the devices to use")
            main_settings.out["std"].print_info("Current connected devices")
            for device in connected_devices:
                print(device)
            sys.exit(1)
        else:
            main_settings.devices.append(list(connected_devices.keys())[0])

    check_device_up(main_settings.devices)

    main_settings.out["std"].print_info("Start ...")

    workers(main_settings)

    main_settings.set_output_std()
    main_settings.out["std"].print_info("Finished")


def workers(settings):
    with ThreadPoolExecutor(max_workers=len(settings.devices)) as executor:
        results = {device: executor.submit(process, device) for device in settings.devices}

    return as_completed(results)


if __name__ == "__main__":
    amdh()
