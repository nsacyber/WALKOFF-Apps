from apps import App, action
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from jinja2 import Environment
import sys


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
    def run_scan(self, target, options):
        nmap_proc = NmapProcess(target, options)
        nmap_proc.run()
        xx = nmap_proc.stdout
        if sys.version_info[0] == 2:
            xx = xx.encode('utf-8')
        nmap_report = NmapParser.parse(nmap_data=xx, data_type='XML')
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
