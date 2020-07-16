<div align="center">
<img src="screenshots/AMDH_800x400.png">
</div>

# AMDH
An Android Mobile Device Hardening written with python3 

## Motivations
AMDH was created to help automating and listing all applications installed devices and also to protect privacy in this "big" age of "data"

## Concept 
Android Mobile Device Hardening is divided on two parts (at this time):
- The first part list the installed applications on the device that use one or more [permissions flagged as dangerous by Android itself](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions) and dump all the APKs
- The second part is based on some CIS (Center of Internet Security) benchmark checks for Android devices and Android master's branch settings documentation ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure)) 

The first part:
- list application installed 
- list dangerous permissions 
- revoke admins receivers for third party Apps
- revoke dangerous permissions for all Apps
- dump APKs of all the Apps except system apps 
- detect malwares based on permissions 

The second part:
- check the system settings (executed at every execution)
- harden the system settings

## Requirement
- Python3 
- Android Debug Bridge (ADB) installed

## Installation 
```
$ git clone https://github.com/SecTheTech/AMDH.git; cd AMDH
```

# Usage
```
$ python amdh.py -h
usage: amdh.py [-h] [-s] [-H] [-a ADB_PATH] [-t {e,d,3,s}] [-D APKS_DUMP_FOLDER] [-rar] [-R]

Android Mobile Device Hardening
By default the script will scan the Android system and Apps without any modification

optional arguments:
  -h, --help            show this help message and exit
  -s                    scan the settings and applications installed
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
  -rar                  remove admin receivers: Remove all admin receivers if the app is not a system App
                        Scan option is required
  -R                    For each app revoke all dangerous permissions
                        Scan option is required
```

## Screenshots
**Scan**
```
python amdh.py -s
```
![Scan Applications](screenshots/scan_apps.png (Applications scan))

![Scan Settings](screenshots/scan_settings.png (Settings scan))

**Harden**
```
python amdh.py -s -H 
```
![Hardening Applications Permissions](screenshots/apps_hardening_permissions.png (Revoking dangerous permissions and removing device admin receiver))

![Hardening Settings](screenshots/settings_hardening.png (Settings Hardening))

**Scan after hardening**

All dangerous permissions have been revoked and admin receivers removed 
```
python amdh.py -s 
```
![Application Scan](screenshots/scan_apps_after_hardening.png (Applications scan after hardening))

> ADB has been disabled and Developpement settings has disappeared from the settings menu.

![Application Scan](screenshots/scan_settings_after_hardening.png (Applications scan after hardening))

## Tests & CIS version
- Tested on Android 8, 9 and 10
- Devices: Nokia, LG, Honor, Xiaomi, OnePlus, AVD
- CIS version: 1.3.0

## Malware detection
MDMA v2.0 include the first version of malware detection. 

It's based on 543 malwares samples uniques permissions that are never used by legitimate applications (based on 480 ligitimate applications).

The python notebook will be added in a different repository.

> Note: Most system Apps will be flagged as "Malware" but can be ignored for this version. 



## Roadmap
- Android application
- Malware detection 
- Applications settings hardening
- GUI

## Participate
Ideas and pull requests are welcome. 

Donation: [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NVWQM4EGVLKLU&source=url).

