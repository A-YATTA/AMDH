# AMDH
<div align="center">
<img src="screenshots/AMDH_800x400.png" title="Android Mobile Device Hardening">
</div>

An Android Mobile Device Hardening written with python3 

## Motivations
AMDH was created to help automating and listing all applications installed devices and also to protect privacy in this "big" age of "data"

## Concept 
Android Mobile Device Hardening is divided on two parts (at this time):
- The first part list the installed applications on the device that use one or more [permissions flagged as dangerous by Android itself](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions) and dump all the APKs
- The second part is based on some CIS (Center of Internet Security) benchmark checks for Android devices and Android master's branch settings documentation ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure)) 

Features:
- Check and harden system's settings
- List current users processes running in background and kill selected ones
- Analyse current installed applications on the device:
  - list dangerous permissions and revokes them
  - compare with permissions used by malwares 
- List applications:
  - uninstall/disable App
  - revoke admins receivers
- Dumps APKs of installed applications
- List current users processes
- Check if the system has pending updates
- Extract packed APKs if exists
- Static analysis for malwares detection. Current detected malwares:
   - ActionSpy
   - WolfRat

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
```


## Screenshots
**Scan**
```
python amdh.py -sA
```
![Malwares detection](screenshots/scan_apps.png (Malwares detection))

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

**Scan after hardening**

```
python amdh.py -sS
```
> ADB has been disabled and Developpement settings has disappeared from the settings menu.

![Applications Scan](screenshots/scan_settings_after_hardening.png (Applications scan after hardening))

**Uninstall/disable apps**
```
python amdh.py -l -D out
``` 
![Applications list](screenshots/uninstall_apps.png (Applications list and uninstalling))
An error occured for the second app because it's a device admin app. Runing with flag '-rar' solved the problem.

**Static Analysis**

![Static Analyis](screenshots/Static_analysis.png (Embedded APK))


## Tests & CIS version
- Tested on Android 8, 9 and 10
- Devices: Nokia, LG, Honor, Xiaomi, OnePlus, AVD
- CIS version: 1.3.0

## Malware detection 
AMDH include malware detection based on most used permissions and combinations by malwares. 

It's based on more than 500 malwares samples uniques permissions that are never used by legitimate applications (based on more than 400 ligitimate applications).

> Note: Most system Apps will be flagged as "Malware" but can be ignored for this version. 

Used malwares collections:
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
| UI                 | Version 1.0 ([AMDH-UI](https://github.com/SecTheTech/AMDH-UI)) |
| Static Analysis    | In Progress   | 
| Forensic mode      | Waiting       |
| Android application| Waiting       | 


## Known Issues
- The command "pm revoke" return exit success code but does not revoke the permissions for some malwares.


## Participation and Ideas
Thank you for the interesting of this project! If you have any ideas on how to improve this tool, please create new issues in this project or send a pull request.  

Donation: [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NVWQM4EGVLKLU&source=url).
