import logging
from apps import App, action
import paramiko
from paramiko.ssh_exception import SSHException
from core.helpers import format_exception_message

logger = logging.getLogger(__name__)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.transport = None
        self.sftp_client = None
        self.is_connected = False

    @action
    def connect(self):
        try:
            self.transport = paramiko.Transport((self.device_fields['ip'], self.device_fields['port']))
            self.transport.connect(username=self.device_fields['username'], password=self.device.get_encrypted_field('password'))
            self.sftp_client = paramiko.SFTPClient.from_transport(self.transport)
            self.is_connected = True
            return 'Success'
        except SSHException as e:
            return 'Could not connect {}'.format(format_exception_message(e)), 'ConnectionError'

    @action
    def get(self, remote_filepath, local_filepath):
        if self.is_connected:
            self.sftp_client.get(remote_filepath, local_filepath)
            return 'Success'
        else:
            return 'Not connected', 'NotConnected'

    @action
    def put(self, local_filepath, remote_filepath):
        if self.is_connected:
            self.sftp_client.put(local_filepath, remote_filepath)
            return 'Success'
        else:
            return 'Not connected', 'NotConnected'

    def shutdown(self):
        try:
            self.transport.close()
        except Exception as e:
            logger.error('Could not shutdown SFTP client. Reason: {}'.format(format_exception_message(e)))


