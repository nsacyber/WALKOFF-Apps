import logging
from apps import App, action
import subprocess

logger = logging.getLogger(__name__)


class Main(App):
    """
       Skeleton example app to build other apps off of
    
       Args:
           name (str): Name of the app
           device (list[str]): List of associated device names
           
    """
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)    # Required to call superconstructor

    @staticmethod
    def execute_command(cmd):
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            return {'error': e.output, 'code': e.returncode}, 'Failure'
        else:
            return output

    @action
    def enable(self):
        """
           Basic self contained function
        """
        return self.execute_command(['ufw', 'enable'])

    @action
    def disable(self):
        """
           Basic self contained function
        """
        return self.execute_command(['ufw', 'disable'])

    @action
    def status(self, verbose=False):
        """
           Basic function that takes in a parameter

           Args:
               test_param (str): String that will be returned
        """
        command = ['ufw', 'status'] if not verbose else ['ufw', 'status', 'verbose']
        return self.execute_command(command)

    @action
    def allow(self, port, from_address='any', to_address='any', protocol='any', comment=None):
        command = (['ufw', 'allow', 'from', from_address, 'to', to_address, 'port', port, 'proto', protocol])
        if comment:
            command.extend(['comment', comment])
        return self.execute_command(command)

    @action
    def allow_service(self, service):
        command = ['ufw', 'allow', service]
        return self.execute_command(command)

    @action
    def deny(self, from_address, protocol='any', port=None, comment=None):
        command = ['ufw', 'deny', 'from', from_address, 'to', protocol]
        if port:
            command.extend(['port', port])
        if comment:
            command.extend(['comment', comment])
        return self.execute_command(command)
