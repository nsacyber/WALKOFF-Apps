from apps import App, action
import winrm
import subprocess
import chardet


@action
def exec_local_command(platform, commands, output_filename=None):
    """
    Use Powershell client to execute commands on the remote server and produce an array of command outputs
    Input:
        args: A String array of commands
    Output:
        result: A String array of the command outputs
    """
    results = []
    status = "Success"
    if platform == "PowerShell.exe (Windows)":
        executable = "powershell.exe"
    elif platform == "PowerShell Core (Cross-Platform)":
        executable = "pwsh"
    else:
        return "Unknown Platform", "ScriptError"

    for command in commands:
        try:
            output = subprocess.check_output([executable, command], shell=True)
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
        if self.device_fields["https"]:
            self.host = "https://" + self.host
        self.username = self.device_fields["username"]
        self.insecure_mode = {}
        if self.device_fields["very_insecure_mode_testing_only"]:
            self.insecure_mode = {"transport": "ntlm", "server_cert_validation": "ignore"}
        self.winrm = winrm.Session(self.host,
                                   auth=(self.username,
                                         self.device.get_encrypted_field("password")),
                                   **self.insecure_mode)

    @action
    def exec_remote_command(self, commands, output_filename=None):

        """
        Use Powershell client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A String array of commands
        Output:
            result: A String array of the command outputs
        """
        results = []
        status = "Success"
        for command in commands:
            rs = self.winrm.run_cmd(command)
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
    def exec_script_remotely(self, local_path, output_filename=None, tab_separated_values=False):
        """
        Use Powershell client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        results = []
        try:
            with open(local_path, 'r') as f:
                script = f.read()
        except IOError as e:
            return e, "FileError"

        # This is because the Kansa scripts are encoded with utf-8-bom
        en = chardet.detect(script)['encoding']
        try:
            script = script.decode(en)
        except UnicodeDecodeError:
            return "Could not decode script file.", "UnknownEncoding"

        script = "$tempin = @'\n{}\n'@".format(script)
        script += ';Invoke-Expression $tempin'

        if tab_separated_values:
            script += '|ConvertTo-CSV -Delimiter "`t" -NoTypeInformation'
            script += '|% { $_ -replace "`"" }'

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
                        f.write(result.replace("\r\n", "\n"))
            except IOError as e:
                return e, "FileError"

        return str(result), status
