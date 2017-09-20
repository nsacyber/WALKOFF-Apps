import logging
from apps import App, action
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import datetime
import os

logger = logging.getLogger(__name__)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)

    @action
    def capture(self, filename=None, timeout=None, count=0, interface=None, packet_filter=None, gz=True):
        """
           Basic self contained function
        """
        if timeout is None and count == 0:
            return 'Either timeout or count must be specified', 'InvalidInput'
        if filename is None:
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
        interface = interface if interface else None
        packets = sniff(iface=interface, timeout=timeout, count=count, filter=packet_filter)

        wrpcap(filename, packets, gz=gz)
        return filename



