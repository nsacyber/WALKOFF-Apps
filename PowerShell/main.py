from apps import App
import winrm


class Main(App):
    def __init__(self, name=None, device=None):
        # The parent app constructor looks for a device configuration and returns that as a dict called self.config
        App.__init__(self, name, device)

        device = self.get_device()
        if device is None:
            self.ip = ""
            self.port = 22
            self.username = ""
            password = ""
        else:
            self.ip = device.ip
            self.port = device.port
            self.username = device.username
            password = device.password

        self.winrm = winrm.Session(self.ip, auth=(self.username, password))

    def execCommand(self, args={}):
        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'command' and the value being a String array of commands
        Output:
            result: A String array of the command outputs
        """
        result = []
        if "command" in args:
            for cmd in args["command"]:
                rs = self.winrm.run_cmd(cmd)
                result.append(rs.std_out)
        return str(result)

    def runLocalScriptRemotely(self, args={}):
        """
        Use Powershell client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        result = []
        if "localPath" in args:
            script = open(args["localPath"], "r").read()
            cmd = "Powershell -Command " + script
            rs = self.winrm.run_ps(cmd)
            result.append(rs.std_out)
        return str(result)
