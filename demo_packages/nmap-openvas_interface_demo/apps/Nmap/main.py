from apps import App, action
from libnmap.parser import NmapParserException
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import networkx
from networkx.readwrite import json_graph
from jinja2 import Environment
import json
import sys
import xml.etree.ElementTree as etree
import logging

logger = logging.getLogger(__name__)

@action
def run_scan(target, options, output_filename=None):
    nmap_proc = NmapProcess(target, options)
    logger.info("Starting nmap scan of {} with options {}".format(target, options))
    nmap_proc.run()
    logger.info("Completed nmap scan of {} with options {}".format(target, options))
    if output_filename is not None:
        try:
            tree = etree.ElementTree(etree.fromstring(nmap_proc.stdout))
            tree.write(output_filename)
        except (IOError, etree.ParseError) as e:
            return e, 'XMLError'

    return nmap_proc.stdout, 'Success'

@action
def scan_results_as_json(nmap_out, is_file=False, output_filename=None):

    xml_str = None
    if is_file:
        try:
            with open(nmap_out, 'r') as f:
                xml_str = f.read().replace("\n", "")
        except IOError as e:
            return e, 'FileReadError'
    else:
        xml_str = nmap_out

    # if sys.version_info[0] == 2:
    #     xml_str = nmap_out.encode('utf-8')

    try:
        nmap_obj = NmapParser.parse(nmap_data=xml_str, data_type='XML')
    except NmapParserException as e:
        return e, 'XMLError'

    ret = []
    for host in nmap_obj.hosts:
        if host.is_up():
            ret.append({'name': host.hostnames.pop() if len(host.hostnames) else host.address,
             'address': host.address,
             'services': [{'port': service.port,
                           'protocol': service.protocol,
                           'state': service.state,
                           'service': service.service,
                           'banner': service.banner} for service in host.services]})

    if output_filename is not None:
        try:
            with open(output_filename, 'w') as f:
                json.dump(ret, f)
        except IOError as e:
            return e, 'FileWriteError'

    return ret, 'Success'


@action
def graph_from_results(port_scan_xml_filename, traceroute_xml_filename, openvas_json_filename, output_filename):

    try:
        with open(port_scan_xml_filename, 'r') as f:
            port_scan_xml_str = f.read().replace("\n", "")

        with open(traceroute_xml_filename, 'r') as f:
            traceroute_xml_str = f.read().replace("\n", "")

        with open(openvas_json_filename, 'r') as f:
            openvas_json_str = json.load(f)
    except IOError as e:
        return e, 'FileReadError'

    if sys.version_info[0] == 2:
        port_scan_xml_str = port_scan_xml_str.encode('utf-8')
        traceroute_xml_str = traceroute_xml_str.encode('utf-8')

    try:
        port_scan_report = NmapParser.parse(nmap_data=port_scan_xml_str, data_type='XML')
        #traceroute_report = NmapParser.parse(nmap_data=traceroute_xml, data_type='XML')
    except NmapParserException as e:
        return e, 'XMLError'

    graph = networkx.Graph()
    graph.add_node("localhost")

    for host in port_scan_report.hosts:
        if host.is_up():
            graph.add_node(host.address, hostnames=host.hostnames, scanned=True, vulns=[])

    try:
        root = etree.fromstring(traceroute_xml_str)
        hosts = root.iterfind('./host')
        for host in hosts:
            # addrs = host.iterfind('./address')
            # host_ipv4 = ""
            # for addr in addrs:
            #     if addr.attrib['addrtype'] == "ipv4":
            #         host_ipv4 = addr.attrib['addr']
            # host_obj = traceroute_report.get_host_byid(host_ipv4)
            if host.find("status").attrib["state"] == 'up':
                hops = host.iterfind('./trace/hop')
                previous = "localhost"
                for hop in hops:
                    if hop.attrib["ipaddr"] in graph.nodes:
                        graph.nodes[hop.attrib["ipaddr"]]['dist'] = hop.attrib['ttl']
                        graph.add_edge(previous, hop.attrib["ipaddr"])
                    else:
                        graph.add_node(hop.attrib["ipaddr"],
                                       dist=hop.attrib['ttl'],
                                       hostnames=[hop.attrib['host']] if 'host' in hop.attrib else None,
                                       scanned=False,
                                       vulns=[])
                        graph.add_edge(previous, hop.attrib["ipaddr"])
                    previous = hop.attrib["ipaddr"]
    except etree.ParseError as e:
        return e, 'XMLError'

    for finding in openvas_json_str:
        if finding['IP'] in graph.nodes:
            graph.nodes[finding['IP']]['vulns'].append(finding)
        else:
            print("{} was in openvas results but not nmap scan".format(finding['IP']))

    j_graph = json_graph.node_link_data(graph)

    try:
        with open(output_filename, 'w') as f:
            json.dump(j_graph, f)

        return j_graph, 'Success'
    except IOError as e:
        return e, 'FileWriteError'


@action
def ports_and_hosts_from_json(nmap_json, is_file=False):
    try:
        if is_file:
            with open(nmap_json) as j:
                obj = json.load(j)
        else:
            obj = json.loads(nmap_json)
    except IOError:
        return False, 'FileReadError'
    except (AttributeError, ValueError) as e:
        return False, 'JSONError'

    r = {"ports": [], "hosts": []}
    for host in obj:
        r["hosts"].append(host["address"])
        for svc in host["services"]:
            if svc["protocol"] == "tcp":
                r["ports"].append("T:" + str(svc["port"]))
            elif svc["protocol"] == "udp":
                r["ports"].append("U:" + str(svc["port"]))

    r["ports"] = ",".join(r["ports"])
    r["hosts"] = ",".join(r["hosts"])

    return r

@action
def scan_results_as_html(self, nmap_json):
    html = '''
    <table style="width:50%;border-collapse:collapse">
            <tr>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Name</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Address</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Port</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Protocol</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">State</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Service</th>
                <th style="background-color:#3c8dbc;color:#f2f2f2;text-align:center;vertical-align:bottom;">Banner</th>
            </tr>
            {% for host in results %}
                {% for service in host['services'] %}
                    <tr>
                        {%- if loop.index%2 == 0 -%}
                            <td style="text-align: left;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ host['name'] }}</td>
                            <td style="text-align: left;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ host['address'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ service['port'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ service['protocol'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ service['state'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ service['service'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;background-color: #cfd4d6;">{{ service['banner'] }}</td>
                        {%- else -%}
                            <td style="text-align: left;vertical-align: center;border-bottom: 1px solid #ddd;">{{ host['name'] }}</td>
                            <td style="text-align: left;vertical-align: center;border-bottom: 1px solid #ddd;">{{ host['address'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;">{{ service['port'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;">{{ service['protocol'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;">{{ service['state'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;">{{ service['service'] }}</td>
                            <td style="text-align: center;vertical-align: center;border-bottom: 1px solid #ddd;">{{ service['banner'] }}</td>
                        {%- endif -%}
                    </tr>
                {% endfor %}
          {% endfor %}
        </table>
    '''
    return Environment().from_string(html).render(results=nmap_json)


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.whitelist = []
        self.blacklist = []

    @action
    def add_host_to_whitelist(self, host):
        self.whitelist.append(host)

    @action
    def add_host_to_blacklist(self, host):
        self.blacklist.append(host)

    @action
    def clear_whitelist(self):
        self.whitelist = []

    @action
    def clear_blacklist(self):
        self.blacklist = []

    @action
    def get_hosts_from_scan(self, target, options=''):
        nmap_proc = NmapProcess(targets=target, options=options)
        nmap_proc.run()

        nmap_report_obj = NmapParser.parse(nmap_proc.stdout)

        hosts = {}

        for host in nmap_report_obj.hosts:
            hosts[host.address] = host.status

        return hosts

    @action
    def run_scan_check_whitelist(self, target, options):
        nmap_proc = NmapProcess(targets=target, options=options)
        nmap_proc.run()

        nmap_report_obj = NmapParser.parse(nmap_proc.stdout)

        count = 0

        for host in nmap_report_obj.hosts:
            if host.status == "up" and host.address not in self.whitelist:
                count = count + 1

        return count

    @action
    def run_scan_check_blacklist(self, target, options):
        nmap_proc = NmapProcess(targets=target, options=options)
        nmap_proc.run()

        nmap_report_obj = NmapParser.parse(nmap_proc.stdout)

        count = 0

        for host in nmap_report_obj.hosts:
            if host.status == "up" and host.address in self.blacklist:
                count = count + 1

        return count

    def shutdown(self):
        print("Nmap Shutting Down")
        return
