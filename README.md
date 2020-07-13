# AMDH
An Android Mobile Device Hardening written with python3 

## Motivations
AMDH was created to help automating and listing all applications installed on their devices and also to protect their privacy in this "big" age of "data"

## Concept 
Android Mobile Device Hardening is divided on two parts (at this time):
- The first part list the installed applications on the device that use one or more [permissions flagged as dangerous by Android itself](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions) and dump all the APKs
- The second part is based on some CIS (Center of Internet Security) benchmark checks for Android devices and Android master's branch settings documentation ([Global settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Global) and [Secure settings](https://developer.android.com/reference/kotlin/android/provider/Settings.Secure)) 

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
usage: amdh.py [-h] [-H] [-a ADB_PATH] [-t {e,d,3,s}] [-D APKS_DUMP_FOLDER]

Android Mobile Device Hardening
By default the script will scan the Android system and Apps without any modification

optional arguments:
  -h, --help            show this help message and exit
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
```

## Tests & CIS version
- Tested on Android 8, 9 and 10
- Devices: Nokia, LG, Honor, Xiaomi, OnePlus, AVD
- CIS version: 1.3.0 

## Roadmap
- Malware detection
- Applications settings hardening
- GUI
- Add APK client instead of using ADB

## Participate
If you would like to participate to this open source project you can make a donation: [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NVWQM4EGVLKLU&source=url).
