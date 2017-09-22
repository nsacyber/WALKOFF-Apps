import logging
from apps import App, action
import os
from datetime import datetime
import json
from core.helpers import format_exception_message
from array import array

logger = logging.getLogger(__name__)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)

    @action
    def remove(self, filename):
        if os.path.exists(filename):
            os.remove(filename)
            return 'Success'
        else:
            return 'File does not exist', 'FileDoesNotExist'

    @action
    def join_path_elements(self, elements):
        print(elements)
        return os.path.join(*elements)

    @action
    def exists_in_directory(self, path):
        return os.path.exists(path)

    @action
    def copy_and_bitswap(self, path_from, path_to=None):
        if not os.path.exists(path_from) or not os.path.isfile(path_from):
            return 'File not found', 'FileNotFound'

        with open(path_from, 'rb') as file_in:
            exe_bytes = array('B', file_in.read())

        exe_bytes.byteswap()

        if not path_to:
            path = os.path.join('.', 'apps', 'FileUtilities', 'data')
            filename = '{}-quarantine.bin'.format(os.path.basename(path_from).split('.')[0])
            if not os.path.exists(path):
                os.mkdir(path)
            filename = os.path.join(path, filename)
        else:
            dirname = os.path.dirname(path_to)
            if dirname and not os.path.exists(dirname):
                os.mkdir(dirname)
            filename = path_to

        with open(filename, 'wb') as file_out:
            exe_bytes.tofile(file_out)

        return filename


    @action
    def read_json(self, filename):
        if not os.path.exists(filename) or not os.path.isfile(filename):
            return 'File does not exist', 'FileDoesNotExist'
        try:
            with open(filename, 'r') as file_in:
                return json.loads(file_in.read())
        except (IOError, OSError) as e:
            return {'error': 'Could not read file', 'reason': format_exception_message(e)}, 'FileDoesNotExist'
        except ValueError:
            return 'Could not read file as json. Invalid JSON', 'InvalidJson'

    @action
    def write_json(self, data, filename):
        dirname = os.path.dirname(filename)
        if dirname and not os.path.exists(dirname):
            os.mkdir(dirname)
        with open(filename, 'w') as config_file:
            config_file.write(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
        return 'Success'

    @action
    def stats(self, filename):

        def add_if_exists(stat, attr, name, results):
            if hasattr(stat, attr):
                results[name] = getattr(stat, attr)

        def add_time_if_exists(stat, attr, name, results):
            if hasattr(stat, attr):
                results[name] = str(datetime.fromtimestamp(getattr(stat, attr)))

        if os.path.exists(filename):
            stats = os.stat(filename)
            result = {}
            add_if_exists(stats, 'st_mode', 'mode', result)
            add_if_exists(stats, 'st_ino', 'inode', result)
            add_if_exists(stats, 'st_dev', 'device', result)
            add_if_exists(stats, 'st_nlink', 'num_links', result)
            add_if_exists(stats, 'st_uid', 'uid', result)
            add_if_exists(stats, 'st_gid', 'gid', result)
            add_if_exists(stats, 'st_size', 'size', result)
            add_if_exists(stats, 'st_blocks', 'blocks', result)
            add_if_exists(stats, 'st_blksize', 'block_size', result)
            add_if_exists(stats, 'st_rdev', 'device_type', result)
            add_if_exists(stats, 'st_flags', 'flags', result)
            add_time_if_exists(stats, 'st_atime', 'access_time', result)
            add_time_if_exists(stats, 'st_mtime', 'modification_time', result)
            add_time_if_exists(stats, 'st_ctime', 'metadata_time', result)

            return result
        else:
            return 'File does not exist', 'FileDoesNotExist'



