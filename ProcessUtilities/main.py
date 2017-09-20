import logging
from apps import App, action
import psutil
from array import array
import os

logger = logging.getLogger(__name__)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)    # Required to call superconstructor

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

        def convert_address(address):
            if len(address) == 2:
                return {'ip': address[0], 'port': address[1]}
            elif len(address) == 1:
                return {'path': address[0]}
            else:
                return {'unknown': str(address)}

        from socket import AF_INET, AF_INET6, AF_UNIX, SOCK_STREAM, SOCK_DGRAM
        connections_jsons = []
        for connection in process.connections():
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
            connection_json['laddr'] = convert_address(connection.laddr)
            connection_json['raddr'] = convert_address(connection.raddr)
            connections_jsons.append(connection_json)
        res['connections'] = connections_jsons
        return res


