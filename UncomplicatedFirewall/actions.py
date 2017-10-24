import logging
from apps import App, action
import subprocess

logger = logging.getLogger(__name__)


def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        return {'error': e.output, 'code': e.returncode}, 'Failure'
    else:
        return output


@action
def enable():
    """
       Basic self contained function
    """
    return execute_command(['ufw', 'enable'])


@action
def disable():
    """
       Basic self contained function
    """
    return execute_command(['ufw', 'disable'])


@action
def status(verbose=False):
    """
       Basic function that takes in a parameter

       Args:
           verbose (bool): Should output be verbose? Defaults to False
    """
    command = ['ufw', 'status'] if not verbose else ['ufw', 'status', 'verbose']
    return execute_command(command)


@action
def allow(port, from_address='any', to_address='any', protocol='any', comment=None):
    command = (['ufw', 'allow', 'from', from_address, 'to', to_address, 'port', port, 'proto', protocol])
    if comment:
        command.extend(['comment', comment])
    return execute_command(command)


@action
def allow_service(service):
    command = ['ufw', 'allow', service]
    return execute_command(command)


@action
def deny(from_address, protocol='any', port=None, comment=None):
    command = ['ufw', 'deny', 'from', from_address, 'to', protocol]
    if port:
        command.extend(['port', port])
    if comment:
        command.extend(['comment', comment])
    return execute_command(command)
