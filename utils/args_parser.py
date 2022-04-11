import argparse
import sys

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
        out["std"].print_error("Option depend on scan application '-sA' ")
        sys.exit(1)

    if args.H and not args.sS:
        out["std"].print_error("Option depend on scan -sS")
        sys.exit(1)

    if print_help:
        parser.print_help(sys.stderr)
        return

    return args