from apps import App
import paramiko, socket, os


class Main(App):
    """
    Initialize the Linux Shell App, which includes initializing the SSH client given the IP address, port, username, and
    password for the remote server
    """

    def __init__(self, name='', device=''):
        App.__init__(self, name, device)

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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

        self.ssh.connect(self.ip, self.port, self.username, password)

    def execCommand(self, args={}):
        """ Use SSH client to execute commands on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'command' and the value being a String array of commands
        Output:
            result: A String array of the command outputs
        """
        result = []
        if "command" in args:
            for cmd in args["command"]:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                output = stdout.read()
                result.append(output)
        return str(result)

    def secureCopy(self, args={}):
        """
        Use SSH client to execute a scp command to copy a local file to the remote server
        Input:
            args: A dictionary with one entry having a key of 'localPath' and the value being the local filepath and another
                  entry having a key of 'remotePath' and the value being the remote filepath
        Output:
            result: A String message of 'SUCCESS' if the file gets copied to the remote server successfully, otherwise, a
            message of 'UNSUCCESSFUL' if any error occurs while trying to copy the file to the remote server
        """
        try:
            print(os.path.abspath(args['localPath']))

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            t = paramiko.Transport(sock)
            t.start_client()
            t.auth_password(self.username, self.password)

            scp_channel = t.open_session()
            lf = open(args["localPath"], 'rb')

            scp_channel.exec_command("scp -v -t %s\n"
                                     % args["remotePath"])
            print(args["remotePath"])
            scp_channel.send('C%s %d %s\n'
                             % (oct(os.stat(args["localPath"]).st_mode)[-4:],
                                os.stat(args["localPath"])[6],
                                args["remotePath"].split('/')[-1]))

            scp_channel.sendall(lf.read())

            lf.close()
            scp_channel.close()
            t.close()
            status = "SUCCESS"
        except Exception as e:
            print(e)
            status = "UNSUCCESSFUL"
        finally:
            sock.close()
            return status

    def runLocalScriptRemotely(self, args={}):
        """ Use SSH client to execute a script on the remote server and produce an array of command outputs
        Input:
            args: A dictionary with the key of 'localPath' and the value being the local filepath of the script
        Output:
            result: A String array of the command outputs
        """
        result = []
        if "localPath" in args:
            script = open(args["localPath"], "r").read()
            cmd = "eval " + script
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.read()
            result.append(output)
        return str(result)

    def shutdown(self):
        """
        Close the SSH connection if there is a SSH connection
        """
        if self.ssh:
            print("SSH Connection Closed")
            self.ssh.close()
        return
