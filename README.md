# AMDH
<div align="center">
<img src="screenshots/AMDH_800x400.png" title="Android Mobile Device Hardening">
</div>

An Android Mobile Device Hardening written with python3 

## Motivations
AMDH was created to help automating and listing all applications installed devices and also to protect privacy in this "big" age of "data"

## Features 
- Check and harden system's settings based on some CIS (Center of Internet Security) benchmark checks for Android devices and Android master's branch settings documentation ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure)) 
- List current users processes running in background and kill selected ones
- Analyse current installed applications on the device:
  - list [dangerous permissions](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions)  and revokes them
  - compare with permissions used by malware 
- List applications:
  - uninstall/disable App
  - revoke admins receivers
- Dumps APKs of installed applications
- List current users processes
- Check if the system has pending updates
- Extract packed APKs if exists
- Static analysis for malware detection. Current detected malware:
   - ActionSpy
   - WolfRat
   - Anubis (version 1: More samples are needed)
- Snapshot the current phone state to a json file:
  - Applications (including system and disabled Apps):
    - first install time
    - last update time
    - current permissons 
    - is the app device admin
  - SMS: current SMS messages
  - Contacts: current list of contacts
  - Backup applications that has backup enabled

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
> Note: For Windows you have to specify the ADB path or edit the variable "adb_windows_path" in config.py

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
  -l                    List numbered applications to disable, uninstall or analyse
  -P                    List current users processes
  -S SNAPSHOT_FILE, --snapshot SNAPSHOT_FILE
                        Write the current state of the phone to a json file and backup application
```

## Screenshots
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
python amdh.py -sA -H 
```
![Hardening Applications Permissions](screenshots/apps_hardening_permissions.png (Revoking dangerous permissions and removing device admin receiver))
```
python amdh.py -sS -H 
```
![Hardening Settings](screenshots/settings_hardening.png (Settings Hardening))

**Uninstall/disable apps**
```
python amdh.py -l
``` 
![Applications list](screenshots/uninstall_apps.png (Applications list and uninstalling))

An error occured for the second app because it's a device admin app. Runing with flag '-rar' solved the problem.

**Static Analysis**
```
python amdh.py -l -D out
``` 

![Static Analyis](screenshots/Static_analysis.png (Embedded APK))


## Tests & CIS version
- Tested on Android 8, 9 and 10
- Devices: Nokia, LG, Honor, Xiaomi, OnePlus, AVD
- CIS version: 1.3.0

## Malware detection 
AMDH include malware detection based on most used permissions and combinations by malware. 

It's based on more than 500 malware samples uniques permissions that are never used by legitimate applications (based on more than 400 ligitimate applications).

> Note: Most system Apps will be flagged as "Malware" but can be ignored for this version. 

Used malware collections:
- [https://github.com/ashishb/android-malware](https://github.com/ashishb/android-malware)
- [https://github.com/sk3ptre/AndroidMalware_2018](https://github.com/sk3ptre/AndroidMalware_2018)
- [https://github.com/sk3ptre/AndroidMalware_2019](https://github.com/sk3ptre/AndroidMalware_2019)
- [https://github.com/sk3ptre/AndroidMalware_2020](https://github.com/sk3ptre/AndroidMalware_2020)


## Static Analysis
- Find, dump and list dangerous permissions of packed APKs
- Dump libraries


## Roadmap
| Feature            | status        | 
| -----------------  |:-------------:| 
| UI                 | Version 2.0 in progress ([AMDH-UI](https://github.com/SecTheTech/AMDH-UI)) |
| Static Analysis    | Waiting       |
| Forensic mode      | In Progress   |
| Android application| Waiting       | 


## Known Issues
- The command "pm revoke" return exit success code but does not revoke the permissions for some malware.


## Participation and Ideas
Thank you for the interesting of this project! If you have any ideas on how to improve this tool, please create new issues in this project or send a pull request.  

Donation: [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NVWQM4EGVLKLU&source=url).
