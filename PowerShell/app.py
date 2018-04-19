from apps import App, action
import winrm
import subprocess
import chardet
import logging

logger = logging.getLogger(__name__)


@action
def exec_local_command(platform, mode, commands, output_filename=None):
    """
    Execute PowerShell command locally, using either Windows PowerShell or cross-platform PowerShell Core if it is installed.
    :param platform: Whether to execute using Windows PowerShell or PowerShell Core
    :param mode: Whether to execute the following commands as cmdlets or script files
    :param commands: List of commands or scripts to execute
    :param output_filename: local path to output results into
    :return: list of results
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
            if mode == "-Command":
                args = [executable, mode, command]
            elif mode == "-File":
                args = [executable, mode] + command.split(" ")
            results.append(subprocess.check_output(args))
        except subprocess.CalledProcessError as e:
            results.append(e.output)
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
        self.host = self.device_fields["host"]
        if self.device_fields["port"] is not None:
            self.host += ":" + self.device_fields["port"]

        if self.device_fields["https"]:
            self.host = "https://" + self.host
        else:
            self.host = "http://" + self.host

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
        Execute the command on the remote host. Only needed if the local system does not have Windows PowerShell or PowerShell Core

        :param commands: list of commands to execute
        :param output_filename: local path to output results into
        :return: list of results
        """
        results = []
        status = "Success"
        for command in commands:
            rs = self.winrm.run_ps(command)
            if rs.status_code == 0:
                results.append(rs.std_out.replace("\r\n", "\n"))
            else:
                results.append(rs.std_err.replace("\r\n", "\n"))
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
        Execute the local script on the remote host. Only needed if the local system does not have Windows PowerShell or PowerShell Core

        :param local_path: path to the script on the local filesystem
        :param output_filename: local path to output results into
        :param tab_separated_values: whether to pipe results into a tsv format. PowerShell script being ran must support this.
        :return: list of results
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
            results.append(rs.std_out.replace("\r\n", "\n"))
        else:
            results.append(rs.std_err.replace("\r\n", "\n"))
            status = "ScriptError"

        if output_filename is not None:
            try:
                with open(output_filename, 'w') as f:
                    for result in results:
                        f.write(result.replace("\r\n", "\n"))
            except IOError as e:
                return e, "FileError"

        return str(result), status
