# AMDH [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/SecTheTech/AMDH.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/SecTheTech/AMDH/context:python)
<div align="center">
<img src="screenshots/AMDH_800x400.png" title="Android Mobile Device Hardening">
</div>
An Android Mobile Device Hardening written with python3

### Android version:
[PoBY-A](https://github.com/SecTheTech/PObY-A)  (Still in development)

## UI
[AMDH-UI](https://github.com/SecTheTech/AMDH-UI)

## Motivations
AMDH was created to help automating and listing all applications installed on devices and also to protect privacy in this "big" age of "data".

## Features 
- [x] Check and harden system's settings based on some CIS (Center of Internet Security) benchmark checks for Android devices and Android master's branch settings documentation ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure))
- [x] List current users processes and kill selected ones
- [x] Analyze current installed applications on the device:
  - [x] list [dangerous permissions](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions)  and revokes them
  - [x] compare with permissions used by malware 
  - [x] generate report.json
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
- [x] Snapshot the current phone state to a json file:
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
  - [ ] Settings
  - [ ] Contacts
- [ ] HTML report

## Requirement
- Python3 
- Android Debug Bridge (ADB) installed
- androguard
- pwntools

## Installation 
```
$ pip install androguard pwntools 
$ git clone https://github.com/SecTheTech/AMDH.git; cd AMDH
```

# Usage
> Note: For Windows you have to specify the ADB path or edit the variable "adb_windows_path" in "config/main.py".

> Warning: when using -l argument with enabled application '-t e', system apps will be listed. Uninstalling system Apps can break your Android system. The use of 'disable' instead of 'uninstall' is recommanded for system Apps.
```
$ python amdh.py -h
usage: amdh.py [-h] [-sS] [-sA] [-H] [-a ADB_PATH] [-t {e,d,3,s}] [-D APKS_DUMP_FOLDER] [-rar] [-R]
               [-l] [-P]

Android Mobile Device Hardening
By default the script will scan the Android system and Apps without any modification

optional arguments:
  -h, --help            show this help message and exit
  -sS                   Scan the system settings
  -sA                   Scan the installed applications
  -H                    Harden system settings /!\ Developer Options and ADB will be disabled /!\ 
  -a ADB_PATH, --adb-path ADB_PATH
                        Path to ADB binary
  -t {e,d,3,s}          Type of applications:
                        	e : enabled Apps
                        	d : disabled Apps
                        	3 : Third party Apps
                        	s : System Apps
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
```

# Documentation & Help
## Tests & CIS version
- Tested on Android 8, 9 and 10
- Devices: Nokia, LG, Honor, Xiaomi, OnePlus, AVD
- CIS version: 1.3.0

## Malware detection 
Malware detection is based on most used permissions and combinations by malware and known malware packages names. Arround 500 malware samples uniques permissions that are never used by legitimate applications (based on more than 400 ligitimate applications). 

Used malware collections:
- [https://github.com/ashishb/android-malware](https://github.com/ashishb/android-malware)
- [https://github.com/sk3ptre/AndroidMalware_2018](https://github.com/sk3ptre/AndroidMalware_2018)
- [https://github.com/sk3ptre/AndroidMalware_2019](https://github.com/sk3ptre/AndroidMalware_2019)
- [https://github.com/sk3ptre/AndroidMalware_2020](https://github.com/sk3ptre/AndroidMalware_2020)

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

# Screenshots & examples
**Scan**
```
python amdh.py -sA
```
![malware detection](screenshots/scan_apps.png (malware detection))

```
python amdh.py -sS
```
![Scan Settings](screenshots/scan_settings.png (Settings scan))

**Harden**
```
python amdh.py -sA -R -rar
```
![Hardening Applications Permissions](screenshots/apps_hardening_permissions.png (Revoking dangerous permissions and removing device admin receiver))
```
python amdh.py -sS -H 
```
![Hardening Settings](screenshots/settings_hardening.png (Settings Hardening))

**Static Analysis**
```
python amdh.py -l -D out
``` 

![Static Analyis](screenshots/static_analysis.png (Embedded APK))

**Snapshot**
```
python amdh.py -S out
```
![Snapshot](screenshots/snapshot.png (Snapshot))

**Snapshot Comparison**
```
$ python amdh.py -cS out/report.json
[-] INFO: List of devices:
[-] INFO: The device emulator-5554 will be used.

[-] INFO: Installed Apps after snapshot was taken
{}
[-] INFO: Apps exists in snapshot
{
    "com.whatsapp": {
        "firstInstallTime": "2020-07-06 18:53:07",
        "lastUpdateTime": "2020-07-06 18:53:07",
        "grantedPermissions": [
            "com.google.android.c2dm.permission.RECEIVE",
            "android.permission.USE_CREDENTIALS",
            "android.permission.MODIFY_AUDIO_SETTINGS",
            "com.google.android.providers.gsf.permission.READ_GSERVICES",
            "android.permission.MANAGE_ACCOUNTS",
            "android.permission.NFC",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.WRITE_SYNC_SETTINGS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "com.whatsapp.permission.BROADCAST",
            "com.android.launcher.permission.UNINSTALL_SHORTCUT",
            "android.permission.READ_PROFILE",
            "android.permission.BLUETOOTH",
            "android.permission.GET_TASKS",
            "android.permission.AUTHENTICATE_ACCOUNTS",
            "android.permission.INTERNET",
            "android.permission.USE_FULL_SCREEN_INTENT",
            "android.permission.BROADCAST_STICKY",
            "com.whatsapp.permission.REGISTRATION",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.USE_FINGERPRINT",
            "android.permission.READ_SYNC_STATS",
            "android.permission.MANAGE_OWN_CALLS",
            "android.permission.READ_SYNC_SETTINGS",
            "com.whatsapp.sticker.READ",
            "android.permission.VIBRATE",
            "com.whatsapp.permission.MAPS_RECEIVE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.USE_BIOMETRIC",
            "com.android.launcher.permission.INSTALL_SHORTCUT",
            "android.permission.WAKE_LOCK"
        ],
        "deviceAdmin": false
    },
    "com.poby.hardroid": {
        "firstInstallTime": "2020-07-18 09:32:53",
        "lastUpdateTime": "2020-07-18 09:53:03",
        "grantedPermissions": [],
        "deviceAdmin": false
    },
    "org.thoughtcrime.securesms": {
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
            "android.permission.WRITE_SYNC_SETTINGS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.READ_PROFILE",
            "android.permission.BLUETOOTH",
            "android.permission.AUTHENTICATE_ACCOUNTS",
            "android.permission.INTERNET",
            "android.permission.WRITE_PROFILE",
            "android.permission.USE_FULL_SCREEN_INTENT",
            "android.permission.BROADCAST_STICKY",
            "android.permission.WRITE_SMS",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.DISABLE_KEYGUARD",
            "android.permission.SET_WALLPAPER",
            "android.permission.USE_FINGERPRINT",
            "android.permission.READ_SYNC_SETTINGS",
            "android.permission.VIBRATE",
            "android.permission.ACCESS_WIFI_STATE",
            "com.android.launcher.permission.INSTALL_SHORTCUT",
            "android.permission.WAKE_LOCK"
        ],
        "deviceAdmin": false
    }
}
[-] INFO: Uninstalled after snapshot was taken
{
    "com.diy_room_decor.dev3": {
        "firstInstallTime": "2020-07-18 07:56:44",
        "lastUpdateTime": "2020-07-18 07:56:44",
        "grantedPermissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE"
        ],
        "deviceAdmin": false,
        "backup": "com.diy_room_decor.dev3.ab"
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
$ python amdh.py -rS out/report.json
[-] INFO: List of devices:
[-] INFO: The device emulator-5554 will be used.

Unlock your phone and press ENTER key to continue
[-] INFO: Starting restore
[-] INFO: Restore finished
[-] INFO: Restore report
{
    "apps": {
        {
            "enthusiast.io.accesspointproximity": {
                "install": "success",
                "backup": "restored"
            },
            "com.my.app": {
                "install": "success",
                "backup": "NOT FOUND"
            },
            "rikka.appops": {
                "install": "success",
                "backup": "restored"
            },
            "com.idea.backup.smscontacts": {
                "install": "success",
                "backup": "restored"
            },
            "net.chobin.android.psdxlite": {
                "install": "success",
                "backup": "restored"
            },
            "com.poby.h": {
                "install": "Failed: Command '['adb', '-s', 'emulator-5556', 'install', 'out/com.poby.h.apk']' returned non-zero exit status 1.",
                "backup": "restored"
            }
        }
    }
}
```


# Participation and Ideas
Thank you for the interesting of this project! If you have any ideas on how to improve this tool, please create new issues in this project or send a pull request.  

## support: 
[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/secthetech)
