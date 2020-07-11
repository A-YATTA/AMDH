# AMDH
An Android Mobile Device Hardening written with python3 

## Motivations
AMDH was created to help people automating and listing all applications installed onn there devices and also to protect there privacy in this "big" age of "data"

## Concept 
Android Mobile Device Hardening is divided on two parts (at this time):
- The first part list the installed applications on the device that use one or more [permissions flagged as dangerous by Google](https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions)
- The second part based on some CIS (Center of Internet Security) recommandations for checking and hardening settings of Android devices.

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
  -t {e,d,3,s}          Type of application:
                                e : enabled Apps
                                d : disabled Apps
                                3 : Third party Apps
                                s : System Apps
  -D APKS_DUMP_FOLDER, --dump-apks APKS_DUMP_FOLDER
                        Dump APKs from device to APKS_DUMP_FOLDER directory
```

## Roadmap
- Application settings hardening
- GUI
- Malware detection
- Add APK client instead of using ADB

## Participate
If you would like to participate to this open source project you can make a donation [HERE](https://www.paypal.com/donate/?token=KYRjlSileLTT8cS-pPPewYjw_jKlsyji1jlMT5RuxaP8s_b3kopjAkgxb2ksXTZ3rE7y3W&country.x=CH&locale.x=CH).
