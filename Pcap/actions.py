import logging
from apps import App, action
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import datetime
import os
import pyshark
import OpenSSL.crypto
import pickle

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


@action
def pyshark_filter_packets(input_filename, display_filter):
    packets = pyshark.FileCapture(input_filename, display_filter=display_filter)
    # dump_packets = []
    for packet in packets:
        print(packet)
        # dump_packets.append(packet)
    return "Success"


@action
def check_cert_fingerprint(packets, bad_certs_file):
    packets = pickle.loads(packets)

    with open(bad_certs_file, 'r') as f:
        bad_certs = f.readlines()
    bad_certs = [f.strip() for f in bad_certs]

    ips = []
    for packet in packets:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,
                                               packet.ssl.handshake_certificate.binary_value)
        fingerprint = cert.digest("sha1").decode("utf-8").replace(":", "").lower()

        if fingerprint in bad_certs:
            ips.append(packet.ip.src)

    return "Success", ips
