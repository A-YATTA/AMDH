from enum import Enum
from sys import platform
import os
from shutil import which
import threading
import argparse
import sys

from core.adb import ADB
from utils.out import Out
from config.main import *

from utils.args_parser import args_parse


# Status of the App
class Status(Enum):
    ENABLED = 'e'
    DISABLED = 'd'
    THIRD_PARTY = '3'
    SYSTEM = 's'


class MainSettings:

    def __init__(self):
        # variables
        self.out = {"std": Out("Linux")}
        self.devices = []
        self.dump_apks = False
        self.apks_dump_folder = locals().get("OUTPUT_DIR", "out")
        self.scan_settings = False
        self.scan_applications = False
        self.harden = False
        self.list_apps = False
        self.list_processes = False
        self.snapshot = False
        self.snapshot_dir = locals().get("SNAPSHOT_DIR", "snap_out")
        self.cmp_snap = False
        self.snapshot_report = locals().get("SNAPSHOT_REPORT_FILE", "snap_report.json")
        self.backup = False
        self.restore_snap = False
        self.snap_to_restore = locals().get("SNAPSHOT_REPORT_FILE", "snap_report.json")
        self.app_type = Status.THIRD_PARTY
        self.revoke = False
        self.rm_admin_recv = False
        self.lock = threading.Lock()
        self.adb_path = locals().get("ADB_BINARY", "adb")
        self.output_dir = locals().get("OUTPUT_DIR", "out")
        self.arguments = None

    def args_parse(self, print_help=False):
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
            self.out["std"].print_error("Option depend on scan application '-sA' ")
            sys.exit(1)

        if args.H and not args.sS:
            self.out["std"].print_error("Option depend on scan -sS")
            sys.exit(1)

        if print_help:
            parser.print_help(sys.stderr)
            return

        self.arguments = args
        return args

    def set_output_std(self):
        if platform == "linux" or platform == "linux2":
            self.out["std"] = Out("Linux")
        elif platform == "darwin":
            self.out["std"] = Out("Darwin")
        elif platform == "win32":
            self.out["std"] = Out("Windows")

    def init_vars(self, arguments=None):
        if arguments:
            self.arguments = arguments

        self.set_output_std()

        if "adb_path" in self.arguments.__dict__.keys():
            self.adb_path = self.arguments.adb_path
        else:
            if platform == "linux" or platform == "linux2" or platform == "darwin":
                if which("adb") is None and not os.path.isfile(ADB_BINARY):
                    self.out["std"].print_error("adb not found please use '-a' to specify the path")
                    args_parse(True)
                    sys.exit(1)
            else:  # Windows
                if which("adb") is None and not os.path.isfile(ADB_WINDOWS_PATH):
                    self.out["std"].print_error("adb not found please use '-a' to specify the path")
                    sys.exit(1)

        if self.arguments.devices:
            if ',' in self.arguments.devices:
                self.devices = self.arguments.devices.split(',')
            elif self.arguments.devices == "ALL":
                self.devices = ADB(self.adb_path).list_devices()
            else:
                self.devices.append(self.arguments.devices)

        elif not ADB(self.adb_path).list_devices():
            self.out["std"].print_error("No device found")
            sys.exit(1)

        if self.arguments.apks_dump_folder:
            self.dump_apks = True
            self.apks_dump_folder = self.arguments.apks_dump_folder

        # Related to scan
        #   scan settings
        if self.arguments.sS:
            self.scan_settings = True

        if self.arguments.sA:
            self.scan_applications = True

        # Hardening param
        if self.arguments.H:
            self.harden = True

        # list applications param
        if self.arguments.l:
            self.list_apps = True

        # list running users processes
        if self.arguments.P:
            self.list_processes = True

        # Related to snapshot
        if self.arguments.snapshot_dir:
            self.snapshot = True
            self.snapshot_dir = self.arguments.snapshot_dir

        # Snapshot comparison
        if self.arguments.snapshot_report:
            self.cmp_snap = True
            self.backup = False
            self.snapshot_report = self.arguments.snapshot_report

        # Snapshot restore
        if self.arguments.snapshot_to_restore:
            self.restore_snap = True
            self.snap_to_restore = self.arguments.snapshot_to_restore

        # Check if one of the operation are chosen
        if not self.scan_settings and not self.scan_applications and not self.dump_apks and not self.harden \
                and not self.list_apps and not self.list_processes and not self.snapshot and not self.cmp_snap \
                and not self.restore_snap:
            self.out["std"].print_error("Please choose an operation")
            self.args_parse(True)
            exit(1)

        self.app_type = Status.THIRD_PARTY.value
        if self.arguments.app_type:
            try:
                self.app_type = Status(self.arguments.app_type)
            except Exception as e:
                self.out["std"].print_error("Invalid application type")

        if self.arguments.R:
            self.revoke = True

        if self.arguments.rar:
            self.rm_admin_recv = True

        if self.app_type.value == 'e':
            self.out["std"].print_info("Scanning system apps may takes a while ...")

        if self.arguments.output_dir:
            self.output_dir = self.arguments.output_dir
            if not os.path.isdir(self.output_dir):
                os.makedirs(self.output_dir)
        else:
            if not os.path.isdir(self.output_dir):
                os.makedirs(self.output_dir)
