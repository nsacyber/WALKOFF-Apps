import logging
from apps import App, action
import subprocess
import json
import pandas as pd
import networkx
import re
from networkx import json_graph
from datetime import datetime
from apps.messaging import Text, Message, send_message, Url, AcceptDecline
from collections import Counter
import ipaddress
from six import text_type
from parsebrologs import ParseBroLogs
from pathlib import Path
import os
import imghdr
import shutil

logger = logging.getLogger(__name__)

http_si = {
    "id.orig_h": 2,
    "id.resp_h": 4,
    "id.resp_p": 5,
    "host": 8,
    "uri": 9,
    "user_agent": 12,
    "status_code": 15,
    "method": 7
}

dns_si = {
    "id.orig_h": 2,
    "id.resp_h": 4,
    "id.resp_p": 5,
    "query": 9,
    "qtype_name": 13,
    "rcode_name": 15,
    "qclass_name": 11
}

def proper_json(filename):
    everything = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                everything.append(json.loads(line))

        with open(filename + ".json", 'w') as f2:
            json.dump(everything, f2)

        return True, 'Success'
    except IOError as e:
        return e, 'FileError'


def pcap_to_bro(filename, json):
    cmd = ['bro', '-r', filename]
    if json:
        cmd.append('tuning/json-log')

    try:
        subprocess.check_output(['bro', '-r', filename])
        return True, 'Success'
    except subprocess.CalledProcessError as e:
        return e, 'BroError'
    except OSError as e:
        return e, 'BroNotFound'


def split_dataframe_to_c3js(df_json):
    o = json.loads(df_json)

    r_columns = []
    for label in o['columns']:
        r_columns.append([label])

    for data_col in o['data']:
        for data_row, new_row in zip(data_col, r_columns):
            new_row.append(data_row)

    r_columns.insert(0, o['index'])
    r_columns[0].insert(0, "index")

    return r_columns


class BroData():
    def __init__(self):
        self.http_log_data = None
        self.dns_log_data = None
        self.conn_log_data = None
        self.roles_to_notify = None
        self.users_to_notify = None
        self.whitelist = None
        self.blacklist = None
        self.otx_domain_iocs = None
        self.otx_ip_iocs = None
        self.malicious_ips_found = None


store = BroData()


@action
def initialize_interface(roles_to_notify, users_to_notify):
    store.roles_to_notify = roles_to_notify
    store.users_to_notify = users_to_notify
    return {"roles": roles_to_notify, "users": users_to_notify}, "Success"


@action
def load_whitelist(filename):
    store.whitelist = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                store.whitelist.add(line.strip())
        return True, "Success"
    except IOError:
        store.whitelist = None
        return False, "FileError"


def analyze_stat(log_data, stat_index):
    # Adapted from https://dgunter.com/2017/09/17/threat-hunting-with-python-prologue-and-basic-http-hunting/
    analysis = {}
    totals = {}

    for line in log_data:
        splitted = line.split('\t')

        try:
            timestamp = datetime.fromtimestamp(float(splitted[0]))
            timestamp = str(timestamp.replace(second=0, microsecond=0))
        except ValueError as e:
            print(e)

        try:
            stat = splitted[stat_index]
        except IndexError as e:
            print(e)

        if stat not in analysis.keys():
            analysis[stat] = {timestamp: 1}
        else:
            if timestamp not in analysis[stat].keys():
                analysis[stat][timestamp] = 1
            else:
                analysis[stat][timestamp] += 1

        if stat not in totals.keys():
            totals[stat] = 1
        else:
            totals[stat] += 1

    # maxi = max(totals.values())
    # mean = np.mean(totals.values())
    # median = np.median(totals.values())
    # stdev = np.std(totals.values())

    return totals, analysis


def send_notif(subject, contents):
    text = Text(contents)
    message = Message(subject=subject, body=[text])
    send_message(
        message, users=store.users_to_notify, roles=store.roles_to_notify)


def check_thresholds(r, log_type):
    if log_type == 'http':
        # HTTP 20X should be the majority?
        status_totals = r['http']['status_code']['totals']
        temp = {"success": 0, "other": 0}
        for key, value in status_totals.items():
            if key.startswith("2"):
                temp['success'] += value
            else:
                temp['other'] += value

        if temp['success'] < temp['other']:
            send_notif(
                "Stat over threshold.",
                "Unusually high volume of non-200 return codes in packet capture."
            )


def check_whitelist(line, log_type):
    if store.whitelist is None:
        return False

    if log_type == 'http':
        stat_index = 8
    elif log_type == 'dns':
        stat_index = 9

    splitted = line.split('\t')
    dest = splitted[4] in store.whitelist or splitted[
        stat_index] in store.whitelist
    src = splitted[2] in store.whitelist
    if dest or src:
        return True
    else:
        return False


@action
def load_indicators(directory, domains_filename, ipv4_filename):

    domains = directory + domains_filename
    ipv4s = directory + ipv4_filename

    store.otx_domain_iocs = {}
    store.otx_ip_iocs = {}

    try:
        with open(domains, 'r') as f:
            for line in f:
                s = line.split(";", 1)
                store.otx_domain_iocs[s[0]] = s[1]

        with open(ipv4s, 'r') as f:
            for line in f:
                s = line.split(";", 1)
                store.otx_ip_iocs[s[0]] = s[1]
    except IOError as e:
        return e, "FileError"
    else:
        return True, "Success"


def check_malicious(line):
    splitted = line.split('\t')

    # make sure splitted 4 exists
    try:
        if not splitted[4]:
            return None
    except IndexError as e:
        print(e)
        return None

    if not ipaddress.ip_address(text_type(splitted[4])).is_global:
        return None

    if not any((store.otx_domain_iocs, store.otx_ip_iocs)):
        print("No indicators loaded.")
        return None

    ip_alerts = None
    domain_alerts = None

    if splitted[4] in store.otx_ip_iocs:
        ip_alerts = splitted[4] + " - " + store.otx_ip_iocs[splitted[4]]

    if splitted[8] in store.otx_domain_iocs:
        domain_alerts = splitted[8] + " - " + store.otx_domain_iocs[
            splitted[8]]

    if any((ip_alerts, domain_alerts)):
        a = {
            'uid': splitted[1],
            'Timestamp': splitted[0],
            'Method': splitted[7],
            'Status': splitted[15],
            'URI': splitted[9]
        }
        b = {'ip': ip_alerts, 'domain': domain_alerts}

        r = {'context': a, 'alerts': b}
        return r
    else:
        return None


@action
def load_http_log(http_log_name):
    try:
        with open(http_log_name, 'r') as f:
            http_file_data = f.read()
    except IOError:
        return False, 'FileError'

    file_data = http_file_data.split('\n')

    store.http_log_data = []
    for line in file_data:
        if line and line[0] is not None and line[0] != "#":
            if not check_whitelist(line, 'http'):
                store.http_log_data.append(line)

    return True, 'Success'


@action
def load_conn_log(conn_log_name):
    try:
        with open(conn_log_name, 'r') as f:
            conn_file_data = f.read()
    except IOError:
        return False, 'FileError'

    file_data = conn_file_data.split('\n')

    store.conn_log_data = {}
    for line in file_data:
        if line and line[0] is not None and line[0] != "#":
            splitted = line.split("\t")
            try:
                store.conn_log_data[splitted[1]] = splitted
            except IndexError as e:
                print(e)

    return True, 'Success'


@action
def load_dns_log(dns_log_name):

    try:
        with open(dns_log_name, 'r') as f:
            dns_file_data = f.read()
    except IOError:
        return False, 'FileError'

    file_data = dns_file_data.split('\n')

    store.dns_log_data = []
    for line in file_data:
        if line and line[0] is not None and line[0] != "#":
            if not check_whitelist(line, 'dns'):
                store.dns_log_data.append(line)

    return True, 'Success'


def add_to_rbh(hosts, ip, mal_request, o_to_d, d_to_o):
    done = False
    for line in hosts:
        if line["IP"] == ip:
            line["# Reqs"] += 1
            line["Sent Bytes"] += o_to_d
            line["Recv Bytes"] += d_to_o
            if mal_request is not None:
                line["# Mal"] += 1
                line["malreqs"].append(mal_request)
            done = True
    if not done:
        raise ValueError


@action
def make_http_netmap():

    num_mal = 0

    if store.http_log_data is None:
        return False, 'NoData'
    g = networkx.DiGraph()
    for line in store.http_log_data:
        s = line.split("\t")

        # The last line might not have more than one element so check and make
        # sure elements 2 and 4 don't throw an error
        try:
            x = s[2]
            y = s[4]
        except IndexError as e:
            print(e)
            continue

        if [s[2], s[4]] in g.edges:
            g.edges[s[2], s[4]]['num_requests'] += 1
        else:
            g.add_edge(
                s[2],
                s[4],
                num_requests=1,
                mal_requests=0,
                sent_bytes=0,
                resp_bytes=0)

            for ip in [s[2], s[4]]:
                g.nodes[ip]['num_requests'] = 1
                g.nodes[ip]['sent_bytes'] = 0
                g.nodes[ip]['resp_bytes'] = 0

            g.nodes[s[2]]['axis'] = 1
            if 'requests_by_host' not in g.nodes[s[2]]:
                g.nodes[s[2]]['requests_by_host'] = []

            g.nodes[s[2]]['requests_by_host'].append({
                "IP": s[4],
                "Hostname": s[8],
                "# Reqs": 1,
                "# Mal": 0,
                "malreqs": [],
                "Sent Bytes": 0,
                "Recv Bytes": 0
            })
            g.nodes[s[4]]['axis'] = 2
            if 'requests_by_host' not in g.nodes[s[4]]:
                g.nodes[s[4]]['requests_by_host'] = []

            g.nodes[s[4]]['requests_by_host'].append({
                "IP": s[2],
                "Hostname": "",
                "# Reqs": 1,
                "# Mal": 0,
                "malreqs": [],
                "Recv Bytes": 0,
                "Sent Bytes": 0
            })

        for ip in [s[2], s[4]]:
            g.nodes[ip]['num_requests'] += 1

            # might not need any of the following try's because of the first one
            try:
                g.nodes[ip]['sent_bytes'] += int(store.conn_log_data[s[1]][9])
                g.nodes[ip]['resp_bytes'] += int(store.conn_log_data[s[1]][10])
            except TypeError as e:
                print(e)

        try:
            g.edges[s[2], s[4]]['sent_bytes'] += int(
                store.conn_log_data[s[1]][9])
            g.edges[s[2], s[4]]['resp_bytes'] += int(
                store.conn_log_data[s[1]][10])
        except TypeError as e:
            print(e)

        mal = check_malicious(line)
        if mal is not None:
            g.edges[s[2], s[4]]['mal_requests'] += 1
            num_mal += 1

        try:
            add_to_rbh(g.nodes[s[2]]['requests_by_host'], s[4], mal,
                       int(store.conn_log_data[s[1]][9]),
                       int(store.conn_log_data[s[1]][10]))
            add_to_rbh(g.nodes[s[4]]['requests_by_host'], s[2], mal,
                       int(store.conn_log_data[s[1]][10]),
                       int(store.conn_log_data[s[1]][9]))
        except TypeError as e:
            print(e)

    jg = json_graph.node_link_data(g)

    filename = "WalkoffBroNetmap.json"
    with open(filename, 'w') as f:
        json.dump(jg, f)

    if num_mal > 0:
        send_notif(
            "Potentially malicious traffic detected in analyzed logs.",
            "{} requests were flagged. Check the Bro interface in WALKOFF for further info."
            .format(num_mal))

    return filename, 'Success'


@action
def analyze_log(log_type):

    if log_type == "http":
        stat_index = http_si
        log_data = store.http_log_data
    elif log_type == "dns":
        stat_index = dns_si
        log_data = store.dns_log_data
    else:
        return False, 'UnknownLog'

    if log_data is None:
        return False, 'LogNotLoaded'

    r = {log_type: {}}
    for stat, index in stat_index.items():
        totals, analysis = analyze_stat(log_data, index)
        analysis_json = pd.DataFrame.from_dict(
            analysis, orient='columns').fillna(0)
        analysis_json = analysis_json.to_json(orient='split')
        analysis_json = split_dataframe_to_c3js(analysis_json)

        max_cols = 50
        if len(analysis_json) > max_cols:
            totals = dict(Counter(totals).most_common(max_cols))
            analysis_json = [
                col for col in analysis_json
                if col[0] in totals.keys() or col[0] == 'index'
            ]

        totals_col = [[k, v] for k, v in totals.items()]
        r[log_type][stat] = {
            "totals": totals,
            "columns": analysis_json,
            "totals_col": totals_col
        }

    check_thresholds(r, log_type)
    filename = log_type + "WalkoffBroAnalysis.json"
    with open(filename, 'w') as f:
        json.dump(r, f)

    return filename, 'Success'


# Go through the entire conn log, checking each IP against the alienvault
# malicious IP's. Builds a string of malicious IP's found, comma delimited.
@action
def conn_check_malicious(conn_log_name):
    mal_ips = ''

    # Open the file
    try:
        with open(conn_log_name, 'r') as f:
            conn_file_data = f.read()
    except IOError:
        return False, 'FileError'

    file_data = conn_file_data.split('\n')

    # Iterate through the file, send each line to check_malicious()
    for line in file_data:
        if line[0:1] == '#' or line[0:1] == '\\':
            continue

        ret = check_malicious(line)

        if ret is None:
            continue
        else:  # there was a malicious IP found, add just the IP to mal_ips
            dash_index = ret['alerts']['ip'].find(' - ')
            mal_ips += ret['alerts']['ip'][0:dash_index] + ','

    if len(mal_ips) > 1:
        return mal_ips, 'MaliciousIPFound'
    else:
        return True, 'NoMaliciousIPFound'


# Make sure the param is a string list of IP's (string because walkoff
# complains about lists). Then store it for later use.
@action
def set_malicious_ips(mal_ips):
    # Matches '<IPv4 Address>,' repeated unlimited times
    pattern = '^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]),)+$'

    if re.match(pattern, mal_ips):
        store.malicious_ips_found = mal_ips
        return True, 'Success'
    else:
        return False, 'Failure'


# Return the 'string list' of malicious IP's
@action
def get_malicious_ips():
    if store.malicious_ips_found:
        return store.malicious_ips_found, 'Success'
    else:
        return False, 'NoMaliciousIPFound'

#Parse traffic based on whether good, bad or unknown.

@action
def parse_traffic(whitelist_input_file, bad_ips, unknown_file_name, log_file_name):
    
    try:
        log_data = ParseBroLogs(log_file_name)
        json_string = log_data.to_json()
        data = json.loads(json_string)

        whitelist = []
        with open(whitelist_input_file, "r") as whitelistinput:
            whitelist.append(whitelistinput.readline().rstrip('\n'))
    except IOError:
        return False, "FileError"

    blacklist = bad_ips.split(",")
    print (blacklist)

    leng = len(data)
    count = 0

    while (count < leng):
        match = False
        for white in whitelist:
            if white == data[count]['id.orig_h']:
                """existing_white_file = Path(white_file_name)
                if existing_white_file:
                    with open(white_file_name, 'a') as white_file:
                        white_str = json.JSONEncoder().encode(data[count])
                        white_file.write(white_str)
                else: #file doesnt exist, create it
                    with open(white_file_name, 'w') as white_file:
                        white_str = json.JSONEncoder().encode(data[count])
                        white_file.write(white_str)"""
                match = True
        if match == False:
            for black in blacklist:
                if black == data[count]['id.orig_h']:
                    match = True    
                    """                    
                    existing_black_file = Path(black_file_name)
                    if existing_black_file:
                    with open(black_file_name, 'a') as black_file:
                        #add entry here
                        black_str = json.JSONEncoder().encode(data[count])
                        black_file.write(black_str)
                    else: #file doesnt exist, create it
                    with open(black_file_name, 'w') as black_file:
                        black_str = json.JSONEncoder().encode(data[count])
                        black_file.write(black_str)"""
        
        if match == False:
            total_packets = str(int(data[count]['orig_pkts']) + int(data[count]['resp_pkts']))
            str_to_write = "Type: "
            str_to_write += data[count]['proto']
            str_to_write += " | "
            str_to_write += data[count]['id.orig_h']
            str_to_write += ' -> '
            str_to_write += data[count]['id.resp_h']
            str_to_write += " | total packets: "
            str_to_write += total_packets
            existing_unknown_file = Path(unknown_file_name)
            if existing_unknown_file:
                with open(unknown_file_name, 'a') as unk_file:
                    #add entry here
                    #unk_str = json.JSONEncoder().encode(data[count])
                    unk_file.write(str_to_write + "\n")
            else: #file doesnt exist, create it
                with open(unknown_file_name, 'w') as unk_file:
                    #unk_str = json.JSONEncoder().encode(data[count])
                    unk_file.write(str_to_write + "\n")
        count += 1
    return True, "Success"
    
@action
def extract_images(resultsDir, pcapFilePath, pathtoBro):
    imageTypes = ['rgb', 'gif', 'pbm', 'pgm', 'ppm', 'tiff', 
                    'rast', 'xbm', 'jpeg', 'bmp', 'png', 'webp', 'exr']

    #pcapFilePath = 'bro/test.pcap'
    broScript = './apps/Bro/bro/extract-all-images.bro'

    if not os.path.exists(resultsDir):
        os.makedirs(resultsDir)

    if not os.path.exists(pathtoBro):
        return False, 'DependencyError'

    args = [pathtoBro, '-C', '-r', pcapFilePath, broScript]
    p = subprocess.Popen(args)

    while p.poll() is None:
        if p.poll() is not None:
            break;

    extractedImagesDir = 'extractedImages'
    extractedFilesDir = 'extract_files'
    if not os.path.exists(os.path.join(resultsDir, extractedImagesDir)):
        os.makedirs(os.path.join(resultsDir, extractedImagesDir))

    for root, dirs, files in os.walk(extractedFilesDir):
        path = os.path.split(root)

        for fil in files:
            try:			
                filesDirPath = os.path.join(root, fil)
                print(len(path) * '---', filesDirPath)

                imagesDirPath = filesDirPath[len(extractedFilesDir)+1:]
                #print(imagesDirPath)

                imageType = imghdr.what(os.path.join(root, fil))
                if imageType in imageTypes:
                    imagesDirs = imagesDirPath.split("/")
                    if not os.path.exists(resultsDir + "/" + extractedImagesDir + "/" + imagesDirs[0]):
                        os.makedirs(resultsDir + "/" + extractedImagesDir + "/" + imagesDirs[0])
                    if not os.path.exists(resultsDir + "/" + extractedImagesDir + "/" + imagesDirs[0] + "/" + imagesDirs[1]):
                        os.makedirs(resultsDir + "/" + extractedImagesDir + "/" + imagesDirs[0] + "/" + imagesDirs[1])

                    print(fil, 'is:', imageType)
                    try:
                        shutil.copyfile(filesDirPath, resultsDir + "/" + extractedImagesDir + "/" + imagesDirPath)
                    except Exception as e:
                        print(e)
                        
            except PermissionError as e:
                print(e)
                return False, "PermissionError"
            except FileNotFoundError as e:
                print(e)
		        
		        
    #for file in filesNotTypes:
    #	print(file)
        
    shutil.rmtree(extractedFilesDir)
    return True, "Success"

