<p align="center">
<a href="https://lgtm.com/projects/g/SecTheTech/AMDH/context:python" >
<img src="https://img.shields.io/lgtm/grade/python/g/SecTheTech/AMDH.svg?logo=lgtm&logoWidth=18" /></a>
<a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-green.svg" /></a>
<a href="https://github.com/secthetech/AMDH"><img src="https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg" /></a>
<a href="https://www.patreon.com/secthetech"><img src="https://img.shields.io/badge/patreon-donate-green.svg" /></a>

</p>

<div align="center">
<img src="images/AMDH_800x400.png" title="Android Mobile Device Hardening">
</div>

# AMDH
Android Mobile Device Hardening written with python3.

### Android App
[PObY-A](https://github.com/ICTrust/PObY-A)

## Motivations
AMDH was created to help automate scanning installed applications on Android devices, detect some known malware
and also to protect privacy.

## Features 
- [x] Check and harden system's settings based on some CIS (Center of Internet Security) benchmark checks for Android 
  devices and Android master's branch settings documentation 
  ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and 
  [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure))
- [x] List current users processes and kill selected ones
- [x] Analyze current installed applications on the device:
  - [x] list [dangerous permissions](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions)  
    and revokes them
  - [x] compare with permissions used by malware 
  - [x] generate report in JSON format
- [x] List applications:
  - [x] uninstall/disable App
  - [x] revoke admins receivers
- [x] Dumps APKs of installed applications
- [x] Check if the system has pending updates
- [x] Extract packed APKs if exists
- [x] Static analysis for malware detection. Current detected malware:
   - [x] ActionSpy
   - [x] WolfRat
   - [x] Anubis
- [x] Snapshot the current phone state to a JSON file:
  - [x] Applications:
    - [x] APK
    - [x] first install time
    - [x] last update time
    - [x] current permissions 
    - [x] is the app device admin
  - [x] SMS: current SMS messages
  - [x] Contacts: current list of contacts
  - [x] Backup applications that has backup enabled
- [x] Snapshots comparison with the current phone state
  - [x] Applications
  - [x] Settings
- [ ] Restore Snapshot
  - [x] Applications
  - [ ] Contacts
- [x] Manage multiple device at once (snapshot comparison and restore are not supported yet)
  - For each device a new thread is created
- [ ] HTML report

## Requirement
- Python3
- Android Debug Bridge (ADB) installed
- androguard
- pwntools

## Installation
```
$ git clone https://github.com/SecTheTech/AMDH.git; cd AMDH
$ python3 -m venv amdh
$ source amdh/bin/activate
(amdh) $ pip install -r requirement.txt
```

# Usage
> Note: For Windows you have to specify the ADB path or edit the variable "adb_windows_path" in "config/main.py".

> Warning: when using -l argument with enabled application '-t e', system apps will be listed. Uninstalling system Apps 
> can break your Android system. The use of 'disable' instead of 'uninstall' is recommended for system Apps.
```
$ python amdh.py -h
usage: amdh.py [-h] [-d DEVICES] [-sS] [-sA] [-H] [-a ADB_PATH] [-t {e,d,3,s}] [-D APKS_DUMP_FOLDER] 
          [-rar] [-R] [-l] [-P] [-S SNAPSHOT_DIR] [-cS SNAPSHOT_REPORT] [-rS SNAPSHOT_TO_RESTORE] [-o OUTPUT_DIR]

Android Mobile Device Hardening

optional arguments:
  -h, --help            show this help message and exit
  -d DEVICES, --devices DEVICES
                        list of devices separated by comma or "ALL" for all connected devices
  -sS                   Scan the system settings
  -sA                   Scan the installed applications
  -H                    Harden system settings /!\ Developer Options and ADB will be disabled /!\ 
  -a ADB_PATH, --adb-path ADB_PATH
                        Path to ADB binary
  -t {e,d,3,s}          Type of applications:
                                e: enabled Apps
                                d: disabled Apps
                                3: Third party Apps
                                s: System Apps
  -D APKS_DUMP_FOLDER, --dump-apks APKS_DUMP_FOLDER
                        Dump APKs from device to APKS_DUMP_FOLDER directory
  -rar                  Remove admin receivers: Remove all admin receivers if the app is not a system App
                        Scan application option "-sA" is required
  -R                    For each app revoke all dangerous permissions
                        Scan application option "-sA" is required
  -l                    List numbered applications to disable, uninstall or analyze
  -P                    List current users processes
  -S SNAPSHOT_DIR, --snapshot SNAPSHOT_DIR
                        Snapshot the current state of the phone to a json file and backup applications into SNAPSHOT_DIR
  -cS SNAPSHOT_REPORT, --cmp-snapshot SNAPSHOT_REPORT
                        Compare SNAPSHOT_REPORT with the current phone state
  -rS SNAPSHOT_TO_RESTORE, --restore-snapshot SNAPSHOT_TO_RESTORE
                        Restore SNAPSHOT_TO_RESTORE
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory for reports and logs. Default: out
```

# Documentation & Help
## Tests & CIS version
- Tested on Android 7.1.1, 8, 9 and 10
- CIS version: 1.3.0

## Malware detection
Compare the granted permissions with the permissions described in the file 
<a href="https://github.com/SecTheTech/AMDH/blob/master/config/malware_perms.json">malware_perms.json</a>. 
The file contains three nodes:
- malware_only: permissions used by malware only
- all: permissions used by malware and legitimate apps
- combinations: permissions combinations used mostly by malware

### malware only permissions
malware only permissions are those used only by malware. The malware analyzed are the ones from the repositories:
- <a href="https://github.com/ashishb/android-malware">https://github.com/ashishb/android-malware</a>
- <a href="https://github.com/sk3ptre/AndroidMalware_2018">https://github.com/sk3ptre/AndroidMalware_2018</a>
- <a href="https://github.com/sk3ptre/AndroidMalware_2019">https://github.com/sk3ptre/AndroidMalware_2019</a>
- <a href="https://github.com/sk3ptre/AndroidMalware_2019">https://github.com/sk3ptre/AndroidMalware_2020</a>

The command "aapt" was used to dump the permissions. The second part was to dump permissions of legitimate Apps 
(around 400 Apps).
malware only permissions are the permissions that are used by malware and never appear in legitimate applications 
analyzed.

### All permissions
All permissions are used by both malware and legitimate applications. The values are percentage of how much 
malware used these permissions comparing to legitimate Apps.

## Static Analysis
- Find, dump and list dangerous permissions of packed APKs using androguard
- Dump libraries and scan for known malware native functions using pwntools

## Snapshot
Snapshot can help to monitor the system state and backup the phone data:
- applications and their permissions 
- system settings 
- Contacts
- SMS

## Known Issues
- The command "pm revoke" return exit success code but does not revoke permissions for some malware.

# Examples
**Scan**
- Scan applications
```
(amdh)$ python amdh.py -d SERIAL1,SERIAL2,SERIAL3 -sA -o reports
```

Two files are generated for each device in the folder "reports": 
- SERIAL.log
- SERIAL_report_apps.json: JSON file that contains for each app its granted permissions, and those that are considered as dangerous.
  Each entry is as follows:
```
{
    "com.package.name": {
        "malware": true,
        "permissions": {
            "all_permissions": [
                "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
                "com.google.android.c2dm.permission.RECEIVE",
                "com.google.android.providers.gsf.permission.READ_GSERVICES",
                "android.permission.WRITE_SYNC_SETTINGS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.AUTHENTICATE_ACCOUNTS"
            ],
            "dangerous_perms": {
                "android.permission.ACCESS_FINE_LOCATION": "This app can get your location based on GPS or network location sources such as cell towers and Wi-Fi networks. These location services must be turned on and available on your phone for the app to be able to use them. This may increase battery consumption.",
                "android.permission.READ_EXTERNAL_STORAGE": "Allows the app to read the contents of your SD card.",
                "android.permission.ACCESS_COARSE_LOCATION": "This app can get your location based on network sources such as cell towers and Wi-Fi networks. These location services must be turned on and available on your phone for the app to be able to use them.",
                "android.permission.CAMERA": "This app can take pictures and record videos using the camera at any time.",
                "android.permission.WRITE_EXTERNAL_STORAGE": "Allows the app to write to the SD card."
            },
            "is_device_admin": false,
        }
    }
}
```
- Scan settings
```
(amdh)$ python amdh.py -sS
```
A report is generated with the name "SERIAL_report_settings.json" in the folder "out" (default output folder).


**Harden**
- applications hardening
```
(amdh)$ python amdh.py -sA -R -rar
```
Same report as scan Apps with addition of these two keys:
```
   "is_device_admin_revoked": true,
   "revoked_dangerous_pemissions": "succeeded"
```
> The key `is_device_admin_revoked` will not be in the result if the app is not device admin

- settings hardening
```
(amdh)$ python amdh.py -sS -H -o reports
```
A report and log file are generated in "reports" directory.

**Static Analysis and multiple Apps uninstall/disable (interactive)**
```
(amdh)$ python amdh.py -l
```

**List current running user processes**
```
(amdh)$ python amdh.py -P -d SERIAL1,SERIAL2 
```

**Snapshot**
```
(amdh)$ python amdh.py -S out
[-] INFO: Start ...
Unlock device SERIAL and press ENTER key to continue
[-] INFO: Finished
```
The folder "out" will contains a subfolder "SERIAL_DATE-TIME". Where DATE-TIME is in the format "YYYY-MM-DD-hh:mm:ss".

**Snapshot Comparison**
```
(amdh)$ python amdh.py -cS out/report.json
[-] INFO: Start ...

[-] INFO: Installed Apps after snapshot was taken
{}
[-] INFO: Apps exists in snapshot
{
    "com.package.name1": {
        "firstInstallTime": "2020-07-06 18:53:07",
        "lastUpdateTime": "2020-07-06 18:53:07",
        "grantedPermissions": [
            "com.google.android.c2dm.permission.RECEIVE",
            "android.permission.USE_CREDENTIALS",
            "android.permission.MODIFY_AUDIO_SETTINGS",
            "com.google.android.providers.gsf.permission.READ_GSERVICES",
            "android.permission.MANAGE_ACCOUNTS",
            "android.permission.NFC"
        ],
        "deviceAdmin": false,
        "apk": "com.package.name1.apk"
    },
    "com.package.name2": {
        "firstInstallTime": "2020-07-10 23:57:53",
        "lastUpdateTime": "2020-07-10 23:57:53",
        "grantedPermissions": [
            "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
            "com.google.android.c2dm.permission.RECEIVE",
            "android.permission.USE_CREDENTIALS",
            "android.permission.MODIFY_AUDIO_SETTINGS",
            "org.thoughtcrime.securesms.ACCESS_SECRETS",
            "android.permission.ACCESS_NOTIFICATION_POLICY",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.WRITE_SYNC_SETTINGS"
        ],
        "deviceAdmin": false,
        "backup": "com.package.name2.ab",
        "apk": "com.package.name2.apk"
    }
}
[-] INFO: Uninstalled after snapshot was taken
{
    "com.package.name3": {
        "firstInstallTime": "2020-07-18 07:56:44",
        "lastUpdateTime": "2020-07-18 07:56:44",
        "grantedPermissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE"
        ],
        "deviceAdmin": false,
        "backup": "com.package.name3.ab",
        "apk": "com.package.name3.apk"
    }
}
[-] INFO: Changed settings after snapshot was taken
{
    "global": [
        "stay_on_while_plugged_in"
    ],
    "secure": [],
    "system": []
}
```

**Snapshot Restore : Apps**
```
(amdh)$ python amdh.py -d SERIAL -rS out/report.json
[-] INFO: Start ...
Unlock device SERIAL and press ENTER key to continue
[-] INFO: Starting restore
[-] INFO: Restore finished
[-] INFO: Restore report
{
    "apps": {
        {
            "com.package.name1": {
                "install": "success",
                "backup": "restored"
            },
            "com.package.name2": {
                "install": "success",
                "backup": "NOT FOUND"
            },
            "com.package.name3": {
                "install": "success",
                "backup": "restored"
            }
        }
    }
}
```

## Participation and Ideas
Thank you for the interesting of this project! If you have any ideas on how to improve this tool, please create new issue or send a pull request.  




