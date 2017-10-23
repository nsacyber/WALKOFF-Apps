import logging
from apps import App, action
import psutil
from array import array
import os
from datetime import datetime
import time
from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, AF_UNIX

logger = logging.getLogger(__name__)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)

    @action
    def get_all_pids(self):
        """
           Basic self contained function
        """
        return psutil.pids()

    @action
    def is_pid_running(self, pid):
        """
           Basic self contained function
        """
        process = psutil.Process(pid)
        return process.is_running()

    @action
    def kill_process(self, pid):
        process = psutil.Process(pid)
        process.kill()
        return ''

    @action
    def get_children(self, pid, with_grandchildren=False):
        process = psutil.Process(pid)
        return process.children(recursive=with_grandchildren)

    @action
    def get_exe(self, pid):
        process = psutil.Process(pid)
        exe = process.exe()
        if exe:
            return exe
        else:
            return 'Executable not found', 'ExecuableNotFound'

    @action
    def get_command_line(self, pid):
        process = psutil.Process(pid)
        command_line = process.cmdline()
        if command_line:
            return process.cmdline()
        else:
            return 'Command line not found', 'CommandLineNotFound'

    @action
    def get_file_argument_to_script_command_line(self, pid):
        process = psutil.Process(pid)
        command_line = process.cmdline()
        if not command_line:
            return 'Command line not found', 'CommandLineNotFound'
        if command_line[0] not in {'python', 'ruby', 'perl', 'ml'}:
            return 'Unknown first argument {}'.format(command_line[0]), 'UnknownOrNoScript'
        if len(command_line) == 1:
            return 'Too few command args', 'UnknownOrNoScript'
        for arg in command_line[1:]:
            if not arg.startswith('-'):
                return arg
        else:
            return 'Unable to find file in command line', 'FileNotFound'

    @action
    def get_all_connections(self,connection_type='all', only_not_localhost=False, only_with_pids=False):
        return self.all_connections_as_json(self.get_filtered_connections(connection_type, only_not_localhost, only_with_pids))

    @staticmethod
    def get_filtered_connections(connection_type='all', only_not_localhost=False, only_with_pids=False):
        if not connection_type:
            connection_type = 'all'
        connections = psutil.net_connections(kind=connection_type)
        if not only_not_localhost and not only_with_pids:
            return connections
        results = connections
        if only_not_localhost:
            results = [connection for connection in results if connection.laddr and connection.laddr[0] != '127.0.0.1']
        if only_with_pids:
            results = [connection for connection in results if connection.pid is not None]
        return results

    @action
    def watch_all_connections(self, watch_time=10, connection_type='all', only_not_localhost=False, only_with_pids=False):
        start = datetime.utcnow()
        results = set()
        while (datetime.utcnow() - start).seconds < watch_time:
            results |= set(Main.get_filtered_connections(connection_type, only_not_localhost, only_with_pids))
            time.sleep(0.01)
        return self.all_connections_as_json(results)

    @action
    def blame_processes_for_ip_connection(self, ip, connection_type='all', watch_time=10):
        start = datetime.utcnow()
        if not connection_type:
            connection_type = 'all'
        results = set()
        while (datetime.utcnow() - start).seconds < watch_time:
            results |= {connection.pid for connection in psutil.net_connections(kind=connection_type)
                        if connection.raddr and connection.raddr[0] == ip and connection.pid is not None}
            time.sleep(0.01)
        return list(results)

    @action
    def get_current_working_directory(self, pid):
        process = psutil.Process(pid)
        return process.cwd()

    @staticmethod
    def convert_address(address):
        if address is None:
            return {'unknown': 'none'}
        if len(address) == 2:
            return {'ip': address[0], 'port': address[1]}
        elif len(address) == 1:
            return {'path': address[0]}
        else:
            return {'unknown': str(address)}

    @staticmethod
    def connection_as_json(connection):
        connection_json = {'fd': connection.fd, 'status': connection.status}
        family = connection.family
        if family == AF_INET:
            family = 'inet'
        elif family == AF_INET6:
            family = 'inet6'
        elif family == AF_UNIX:
            family = 'unix'
        connection_type = connection.type
        if connection_type == SOCK_STREAM:
            connection_type = 'stream'
        elif connection_type == SOCK_DGRAM:
            connection_type = 'dgram'
        connection_json['type'] = connection_type
        connection_json['family'] = family
        connection_json['laddr'] = Main.convert_address(connection.laddr)
        connection_json['raddr'] = Main.convert_address(connection.raddr)
        return connection_json

    @staticmethod
    def all_connections_as_json(connections):
        return [Main.connection_as_json(connection) for connection in connections if connection is not None]

    @action
    def copy_and_reverse_exe(self, pid, filename=None):
        process = psutil.Process(pid)
        exe = process.exe()
        if not exe:
            return 'Exe not found', 'ExeNotFound'
        exe_bytes = array('B', open(exe, 'rb').read())
        exe_bytes.byteswap()
        if filename is None:
            path = os.path.join('.', 'apps', 'ProcessUtilities', 'data')
            filename = '{}-quarantine.bin'.format(pid)
            if not os.path.exists(path):
                os.mkdir(path)
            filename = os.path.join(path, filename)
        else:
            dirname = os.path.dirname(filename)
            if dirname and not os.path.exists(dirname):
                os.mkdir(dirname)
        exe_bytes.tofile(open(filename, 'wb'))
        return filename

    @action
    def get_process_info(self, pid):
        process = psutil.Process(pid)
        res = {}
        for key, value in process.as_dict().items():
            try:
                res[key] = dict(value.__dict__)
            except AttributeError:
                if isinstance(value, list):
                    ret = []
                    for x in value:
                        try:
                            ret.append(dict(x.__dict__))
                        except AttributeError:
                            ret.append(x)
                else:
                    res[key] = value
        if 'memory_info' in res and 'memory_full_info' in res:
            res['memory_info'] = res.pop('memory_full_info')

        connections_jsons = []
        for connection in process.connections():
            connections_jsons.append(self.connection_as_json(connection))
        res['connections'] = connections_jsons
        return res
