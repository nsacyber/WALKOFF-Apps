from apps import App, action
import winrm
import subprocess


@action
def exec_local_command(command, output_filename=None):
    """
    Use Powershell client to execute commands on the remote server and produce an array of command outputs
    Input:
        args: A String array of commands
    Output:
        result: A String array of the command outputs
    """
    results = []
    status = "Success"
    for cmd in command:
        try:
            output = subprocess.check_output(["powershell.exe", cmd], shell=True)
            results.append(output)
        except subprocess.CalledProcessError as e:
            results.append(e)
            status = "ScriptError"

    if output_filename is not None:
        try:
            with open(output_filename, 'w') as f:
                for result in results:
                    f.write(result)
        except IOError as e:
            return e, "FileError"

    return str(results), status


class PowerShell(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.host = "{}:{}".format(self.device_fields["host"], self.device_fields["port"])
        self.username = self.device_fields["username"]
        self.insecure_mode = {}
        if self.device_fields["very_insecure_mode_testing_only"]:
            self.insecure_mode = {"transport": "ntlm", "server_cert_validation": "ignore"}
        self.winrm = None

    @action
    def exec_remote_command(self, command, output_filename=None):

        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A String array of commands
        Output:
            result: A String array of the command outputs
        """

        self.winrm = winrm.Session(self.host,
                                   auth=(self.username,
                                         self.device.get_encrypted_field("password")),
                                   **self.insecure_mode)
        results = []
        status = "Success"
        for cmd in command:
            rs = self.winrm.run_cmd(cmd)
            if rs.status_code == 0:
                results.append(rs.std_out)
            else:
                results.append(rs.std_err)
                status = "ScriptError"
                break

        if output_filename is not None:
            try:
                with open(output_filename, 'w') as f:
                    for result in results:
                        f.write(result)
            except IOError as e:
                return e, "FileError"

        return str(results), status

    @action
    def exec_script_remotely(self, local_path, output_filename=None):
        """
        Use Powershell client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        self.winrm = winrm.Session(self.host,
                                   auth=(self.username,
                                         self.device.get_encrypted_field("password")),
                                   **self.insecure_mode)
        results = []
        try:
            with open(local_path, 'r') as f:
                script = f.read()
        except IOError as e:
            return e, "FileError"

        rs = self.winrm.run_ps(script)
        status = "Success"

        if rs.status_code == 0:
            results.append(rs.std_out)
        else:
            results.append(rs.std_err)
            status = "ScriptError"

        if output_filename is not None:
            try:
                with open(output_filename, 'w') as f:
                    for result in results:
                        f.write(result)
            except IOError as e:
                return e, "FileError"

        return str(result), status
