import logging
from apps import App, action
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import datetime
import os

logger = logging.getLogger(__name__)


@action
def capture(filename=None, timeout=None, count=0, interface=None, packet_filter=None, gz=True):
    """
       Basic self contained function
    """
    if timeout is None and count == 0:
        return 'Either timeout or count must be specified', 'InvalidInput'
    if not filename:
        filename = str(datetime.datetime.utcnow())
        filename = filename.replace(':', '-')
        filename = filename.replace('.', '-')
        filename += '.pcap'
        path = os.path.join('.', 'apps', 'Pcap', 'data')
        if not os.path.exists(path):
            os.mkdir(path)
        filename = os.path.join(path, filename)
    else:
        dirname = os.path.dirname(filename)
        if dirname and not os.path.exists(dirname):
            os.mkdir(dirname)
        if not filename.endswith('.pcap'):
            filename += '.pcap'
    args = {}
    if timeout is not None:
        args['timeout'] = timeout
    if count is not None:
        args['count'] = count
    if interface:
        args['iface'] = interface
    if packet_filter:
        args['filter'] = packet_filter
    print(args)
    packets = sniff(**args)
    print(filename)

    wrpcap(filename, packets, gz=gz)
    return filename



