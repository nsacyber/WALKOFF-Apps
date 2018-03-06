from apps import App, action
import winrm
import subprocess


@action
def exec_local_command(command):
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


class PowerShell(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.ip = self.device_fields["ip"]
        self.port = self.device_fields["port"]
        self.username = self.device_fields["username"]
        self.winrm = None

    @action
    def exec_remote_command(self, command):

        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A String array of commands
        Output:
            result: A String array of the command outputs
        """
        self.winrm = winrm.Session(self.ip, auth=(self.username, self.device.get_encrypted_field("password")))
        result = []
        for cmd in command:
            rs = self.winrm.run_cmd(cmd)
            result.append(rs.std_out)

        return str(result)

    @action
    def exec_script_remotely(self, local_path):
        """
        Use Powershell client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        self.winrm = winrm.Session(self.ip, auth=(self.username, self.device.get_encrypted_field("password")))
        result = []
        script = open(local_path, "r").read()
        cmd = "Powershell -Command " + script
        rs = self.winrm.run_ps(cmd)
        result.append(rs.std_out)

        return str(result)
