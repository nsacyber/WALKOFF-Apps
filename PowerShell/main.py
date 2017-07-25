from apps import App, action
import winrm
import subprocess

class Main(App):
    def __init__(self, name=None, device=None):
        # The parent app constructor looks for a device configuration and returns that as a dict called self.config
        App.__init__(self, name, device)

        device = self.get_device()
        if device is None:
            self.ip = "127.0.0.1"
            self.port = 22
            self.username = ""
            password = ""

        else:
            self.ip = device.ip
            self.port = device.port
            self.username = device.username
            password = device.password



    @action
    def execLocalCommand(self, command):
        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A String array of commands
        Output:
            result: A String array of the command outputs
        """
        result = []
        for cmd in command:
            output = subprocess.check_output(["powershell.exe", cmd], shell=True)
            result.append(output)

        return str(result)

    @action
    def execRemoteCommand(self, command):

        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A String array of commands
        Output:
            result: A String array of the command outputs
        """
        self.winrm = winrm.Session(self.ip, auth=(self.username, password))
        result = []
        for cmd in command:
            rs = self.winrm.run_cmd(cmd)
            result.append(rs.std_out)

        return str(result)

    @action
    def runLocalScriptRemotely(self, localPath):
        """
        Use Powershell client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        self.winrm = winrm.Session(self.ip, auth=(self.username, password))
        result = []
        script = open(localPath, "r").read()
        cmd = "Powershell -Command " + script
        rs = self.winrm.run_ps(cmd)
        result.append(rs.std_out)

        return str(result)
