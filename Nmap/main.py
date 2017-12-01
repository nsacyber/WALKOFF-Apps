from apps import App, action
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import networkx
from networkx.readwrite import json_graph
from jinja2 import Environment
import json
import sys


@action
def run_scan(target, options):
    nmap_proc = NmapProcess(target, options)
    nmap_proc.run()
    return nmap_proc.stdout


@action
def scan_results_as_json(nmap_out):
    if sys.version_info[0] == 2:
        nmap_out = nmap_out.encode('utf-8')
    nmap_report = NmapParser.parse(nmap_data=nmap_out, data_type='XML')
    ret = [{'name': host.hostnames.pop() if len(host.hostnames) else host.address,
            'address': host.address,
            'services': [{'port': service.port,
                          'protocol': service.protocol,
                          'state': service.state,
                          'service': service.service,
                          'banner': service.banner} for service in host.services]}
           for host in nmap_report.hosts]
    return ret


@action
def graph_from_results(nmap_out):
    graph = networkx.Graph()
    my_ip = nmap_out.hosts[-1].address
    for host in nmap_out.hosts:
        if host.is_up():
            graph.add_node(host.address)
            graph.add_edge(host.address, my_ip)
    j_graph = json_graph.node_link_data(graph)
    return j_graph


@action
def ports_and_hosts_from_json(string, is_file=False):
    try:
        if is_file:
            with open(string) as j:
                obj = json.load(j)
        else:
            obj = json.loads(string)
    except IOError:
        return False, 'NotExists'
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
def scan_results_as_html(self, results):
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
    return Environment().from_string(html).render(results=results)


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
