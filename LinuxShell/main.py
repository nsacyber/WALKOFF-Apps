from apps import App, action
import paramiko, socket, os
from scp import SCPClient
import hashlib

class LinuxShellApp(App):
    """
    Initialize the Linux Shell App, which includes initializing the SSH client given the IP address, port, username, and
    password for the remote server
    """

    def __init__(self, name='', device=''):
        App.__init__(self, name, device)

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.ip = self.device_fields["ip"]
        self.port = self.device_fields["port"]
        self.username = self.device_fields["username"]

        self.ssh.connect(self.ip, self.port, self.username, self.device.get_encrypted_field('password'))

    @action
    def execCommand(self, command):
        """ Use SSH client to execute commands on the remote server and produce an array of command outputs
        Input:
            command: An array of string commands
        Output:
            result: A String array of the command outputs
        """
        result = []
        for cmd in command:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.read()
            result.append(output)
        return str(result), "Success"

    def file_hash(self, filename):
        m = hashlib.md5()
        with open(filename, "rb") as f:
            buf = f.read()
            m.update(buf)
        a = m.hexdigest()
        return str(a)

    def fileExists(self, localPath, remotePath):
        cmd = '[[ -f {} ]] && echo "1" || echo "0"; '.format(remotePath + "/" + os.path.basename(localPath))
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        if stdout.read().decode("ascii").strip() == "0":
            return False
        return True

    @action
    def secureCopy(self, localPath, remotePath):
        if not self.fileExists(localPath, remotePath):
            localFileHash = self.file_hash(localPath)

            with SCPClient(self.ssh.get_transport()) as scp:
                scp.put(localPath, remotePath)


            cmd = "md5sum {}".format(remotePath + "/" + os.path.basename(localPath))

            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            if stdout.read().decode("utf-8").split(" ")[0] == localFileHash:
                return "True", "Success"
            else:
                return "Destination file does not match source file", "Error"
        else:
            return "False", "FileExists"

    @action
    def runLocalScriptRemotely(self, localPath):
        """ Use SSH client to execute a script on the remote server and produce an array of command outputs
        Input:
            localPath: the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        result = []
        script = open(localPath, "r").read()
        cmd = "eval " + script
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        output = stdout.read()
        result.append(output)
        return str(result), "Success"

    def shutdown(self):
        """
        Close the SSH connection if there is a SSH connection
        """
        if self.ssh:
            self.ssh.close()
        return
