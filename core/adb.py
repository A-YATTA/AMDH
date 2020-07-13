from subprocess import run, PIPE
import re


class ADB:

    def __init__(self, adbPath="", deviceID=""):
        self.adbPath = adbPath
        self.deviceID = deviceID

    def adb_exec(self, commandsArray):

        if not self.deviceID :
            commandsArray.insert(0, self.adbPath)
            result = run(commandsArray,
                         stdout=PIPE, stderr=PIPE, check=True,
                         universal_newlines=True)
        else:
            commandsArray.insert(0, self.adbPath)
            commandsArray.insert(1, "-s")
            commandsArray.insert(2, self.deviceID)
            result = run(commandsArray,
                stdout=PIPE, stderr=PIPE, check=True,
                universal_newlines=True)

        return result.stdout

    
    def list_devices(self):
        devices = {}
        command_result = self.adb_exec(["devices"]).split("\n")[1:]
        for line in command_result:
            if line:
                temp = line.split("\t")
                devices.update({temp[0].strip(): temp[1].strip()})
        return devices


    # TO-DO: exceptions => apps not available
    # status => Enum in application.py
    def list_installed_packages(self, status):
        adbCommand = ["shell", "pm", "list", "packages", "-"+status]
        outputCommand = self.adb_exec(adbCommand)
        listInstalledApps = []
        for line in outputCommand.split("\n"):
            if not (":" in line):
                continue
            listInstalledApps.append(line.split(":")[1])

        return listInstalledApps

    # if the outputFile exist, it will be overriten
    def dump_apk_from_device(self, package_name, outputFile="base.apk"):
        adbPathCommand = ["shell", "pm", "path", str(package_name)]
        apkPath = (self.adb_exec(adbPathCommand)).split("\n")[0].split(":")[1]

        adb_pull_command = ["pull", apkPath.strip(), outputFile]
        output_pull_command = self.adb_exec(adb_pull_command)

        if "1 file pulled" in output_pull_command:
            return True

        return False

    def uninstall_app(self, package_name):
        adb_uninstall_command = ["uninstall", package_name]
        output_uninstall_command = self.adb_exec(adb_uninstall_command)

        if "Success" in output_uninstall_command:
            return True

        return False

    # param is an array of arguments
    def dumpsys(self, params):
        dumpsys_command = ["shell", "dumpsys"] + params
        return self.adb_exec(dumpsys_command)

    # return list of permissions
    # output = dumpsys package package_name
    def get_req_perms_dumpsys_package(self, dumpsys_output):
        if "requested permissions" in dumpsys_output:
            p = re.compile(r'(?<=requested permissions:).+?(?=(User [0-9]+:|install permissions))')
            perms_part = re.search(p, dumpsys_output.replace("\n", " "))
            perms_part_tmp = perms_part.group(0).strip().replace(": granted=true", "")
            return re.split(" +", perms_part_tmp)
            # return ' '.join(re.search(p,dumpsys_output.replace("\n", "")).group(0).split()).split(" ")
        return []

    def get_install_perms_dumpsys_package(self, dumpsys_output):
        
        if "install permissions" in dumpsys_output:
            
            p = re.compile(r'(?<=install permissions:).+?(?=User [0-9]+:)')
            perms_part = re.search(p, dumpsys_output.replace("\n", " "))
            perms_part_tmp = perms_part.group(0).strip().replace(": granted=true", "")
            return re.split(" +", perms_part_tmp)

        return []


    # section can be : secure, global or system 
    def content_query(self, settings_section, key):
        command = ["shell", "content", "query", "--uri", "content://settings/" + settings_section,
                   "--projection", "name:value", "--where", "'name=\"" + key + "\"'"]
        return self.adb_exec(command)

    def content_delete(self, settings_section, key):
        command = ["shell", "content", "delete", "--uri", "content://settings/" + settings_section,
                   "--where", "'name=\"" + key + "\"'"]
        return self.adb_exec(command)

    def content_insert(self, settings_section, key, expected_value, expected_value_type):
        if expected_value_type not in ['b', 's', 'i', 'l', 'f', 'd']:
            return "value type is not recognized! type sould be: b,s,i,l,f or d"

        command = ["shell", "content", "insert", "--uri", "content://settings/" + settings_section,
                   "--bind", "name:s:" + key, "--bind value:" + expected_value_type + ":" + expected_value]
        return self.adb_exec(command)
