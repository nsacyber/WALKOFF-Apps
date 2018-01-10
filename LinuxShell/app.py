from apps import App, action
import paramiko, socket, os
import json


class LinuxShell(App):
    """
    Initialize the Linux Shell App, which includes initializing the SSH client given the IP address, port, username, and
    password for the remote server
    """

    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.ip = self.device_fields['ip']
        self.port = self.device_fields['port']
        self.username = self.device_fields['username']

        self.ssh.connect(self.ip, self.port, self.username, self.device.get_encrypted_field('password'))

    @action
    def exec_command(self, args):
        """ Use SSH client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A string array of commands
        Output:
            result: A String array of the command outputs
        """
        result = []
        for cmd in args:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.read()
            result.append(output)
        return str(result), 'Success'

    @action
    def scp_get(self, local_path, remote_path):
        """
        Use SSH client to execute a scp command to copy a local file to the remote server
        Input:
            args: local_path and remote_path of file
        Output:
            Success/Failure
        """
        try:
            print(os.path.abspath(local_path))

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            t = paramiko.Transport(sock)
            t.start_client()
            t.auth_password(self.username, self.device.get_encrypted_field('password'))

            scp_channel = t.open_session()
            lf = open(local_path, 'rb')

            scp_channel.exec_command("scp -v -t %s\n"
                                     % remote_path)
            print(remote_path)
            scp_channel.send('C%s %d %s\n'
                             % (oct(os.stat(local_path).st_mode)[-4:],
                                os.stat(local_path)[6],
                                remote_path.split('/')[-1]))

            scp_channel.sendall(lf.read())

            lf.close()
            scp_channel.close()
            t.close()
            status = True, 'Success'
        except Exception as e:
            print(e)
            status = False, 'Failure'
        finally:
            sock.close()
            return status

    @action
    def sftp_put(self, local_path, remote_path):
        """
        Use SSH client to copy a local file to the remote server using sftp
        Input:
            args: local_path and remote_path of file
        Output:
            Success/Failure
        """
        sftp = self.ssh.open_sftp()
        result = sftp.put(local_path, remote_path)
        sftp.close()
        return str(result), 'Success'

    @action
    def sftp_get(self, remote_path, local_path):
        """
        Use SSH client to copy a remote file to local using sftp
        Input:
            args: local_path and remote_path of file
        Output:
            Success/Failure
        """
        sftp = self.ssh.open_sftp()
        result = sftp.get(remote_path, local_path)
        sftp.close()
        return str(result), 'Success'

    @action
    def run_shell_script_remotely(self, local_path):
        """ Use SSH client to execute a shell script on the remote server and produce an array of command outputs
        Input:
            args: local filepath of the shell script
        Output:
            result: A String array of the command outputs
        """
        result = []
        script = open(local_path, "r").read()
        cmd = "eval " + script
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        output = stdout.read()
        result.append(output)
        return str(result), 'Success'

    @action
    def shutdown(self):
        """
        Close the SSH connection if there is a SSH connection
        """
        if self.ssh:
            print("SSH Connection Closed")
            self.ssh.close()
        return True, 'Success'
