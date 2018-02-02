import logging
from apps import App, action
# from bat_min import bro_log_reader
import subprocess
import json
import pandas as pd
import numpy as np
from datetime import datetime
from apps.messaging import Text, Message, send_message, Url, AcceptDecline
from collections import Counter

logger = logging.getLogger(__name__)

http_stat_index = {"id.orig_h": 2,
                   "id.resp_h": 4,
                   "id.resp_p": 5,
                   "host": 8,
                   "uri": 9,
                   "user_agent": 12,
                   "status_code": 15,
                   "method": 7}

dns_stat_index = {"id.orig_h": 2,
                  "id.resp_h": 4,
                  "id.resp_p": 5,
                  "query": 9,
                  "qtype_name": 13,
                  "rcode_name": 15,
                  "qclass_name": 11}


def proper_json(filename):
    everything = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                everything.append(json.loads(line))

        with open(filename+".json", 'w') as f2:
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
        # if len(new_row) < 10:
            new_row.append(data_row)

    r_columns.insert(0, o['index'])
    r_columns[0].insert(0, "index")

    return r_columns

#
# class Bro(App):
#     """
#        Bro app to analyze bro logs
#
#        Args:
#            name (str): Name of the app
#            device (list[str]): List of associated device names
#
#     """
#     def __init__(self, name=None, device=None):
#         App.__init__(self, name, device)
#         # self.address = self.device_fields['address']
#         # self.port = self.device_fields['port']
#         self.http_log_data = None
#         self.http_stat_thresh = None
#         self.dns_log_data = None
#         self.dns_stat_thresh = None
#         self.roles_to_notify = None
#         self.users_to_notify = None


class BroData():
    def __init__(self):
        self.http_log_data = None
        self.dns_log_data = None
        self.roles_to_notify = None
        self.users_to_notify = None


store = BroData()


@action
def initialize_interface(roles_to_notify, users_to_notify):
    store.roles_to_notify = roles_to_notify
    store.users_to_notify = users_to_notify
    return {"roles": roles_to_notify,
            "users": users_to_notify}

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
            store.http_log_data.append(line)

    # store.http_stat_names = http_stat_names

    return True, 'Success'


def analyze_stat(log_data, stat_index):
    # Adapted from https://dgunter.com/2017/09/17/threat-hunting-with-python-prologue-and-basic-http-hunting/
    analysis = {}
    totals = {}
    for line in log_data:
        splitted = line.split('\t')

        timestamp = datetime.fromtimestamp(float(splitted[0]))
        timestamp = str(timestamp.replace(second=0, microsecond=0))

        stat = splitted[stat_index]

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


def send_notif(contents):
    text = Text(contents)
    message = Message(subject="Stat over threshold.", body=[text])
    send_message(message, users=store.users_to_notify, roles=store.roles_to_notify)


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
            send_notif("Unusually high volume of non-200 return codes in packet capture.")



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
            store.dns_log_data.append(line)

    return True, 'Success'


@action
def analyze_log(log_type):

    if log_type == "http":
        stat_index = http_stat_index
        log_data = store.http_log_data
    elif log_type == "dns":
        stat_index = dns_stat_index
        log_data = store.dns_log_data
    else:
        return False, 'UnknownLog'

    r = {log_type: {}}
    for stat, index in stat_index.items():
        totals, analysis = analyze_stat(log_data, index)
        analysis_json = pd.DataFrame.from_dict(analysis, orient='columns').fillna(0)
        analysis_json = analysis_json.to_json(orient='split')
        analysis_json = split_dataframe_to_c3js(analysis_json)

        max_cols = 50
        if len(analysis_json) > max_cols:
            totals = dict(Counter(totals).most_common(max_cols))
            analysis_json = [col for col in analysis_json if col[0] in totals.keys() or col[0] == 'index']

        totals_col = [[k, v] for k, v in totals.items()]
        r[log_type][stat] = {"totals": totals, "columns": analysis_json, "totals_col": totals_col}

    check_thresholds(r, log_type)

    return r, 'Success'
#
# @action
# def pcap_to_bro_http_json_log(self, filename):
#     r = pcap_to_bro(filename, True)
#     if r is not (True, 'Success'):
#         return r
#
#     return proper_json('http.log')
#
# @action
# def pcap_to_bro_dns_json_log(self, filename):
#     r = pcap_to_bro(filename, True)
#     if r is not (True, 'Success'):
#         return r
#
#     return proper_json('dns.log')
