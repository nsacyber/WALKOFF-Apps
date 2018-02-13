from interfaces import dispatcher, AppBlueprint
from walkoff.events import WalkoffEvent
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
import json

blueprint = AppBlueprint(blueprint=Blueprint('Bro_Demo', __name__))

analysis_data = {'dns': None, 'http': None}
analysis_filenames = {'dns': "dnsWalkoffBroAnalysis.json", 'http': "httpWalkoffBroAnalysis.json"}
netmap = None
netmap_filename = "WalkoffBroNetmap.json"


@dispatcher.on_app_actions('Bro', actions=['make http netmap'],
                           events=WalkoffEvent.ActionExecutionSuccess)
def get_netmap(data):
    global netmap
    global netmap_filename
    netmap_filename = data['data']['result']
    with open(netmap_filename, 'r') as f:
        netmap = json.load(f)


@dispatcher.on_app_actions('Bro', actions=['analyze log'],
                           events=WalkoffEvent.ActionExecutionSuccess)
def get_analysis(data):

    log_type = data['arguments'][0]['value']
    if log_type in ('dns', 'http'):
        global analysis_data
        global analysis_filenames
        analysis_filenames[log_type] = data['data']['result']

        with open(analysis_filenames[log_type], 'r') as f:
            analysis_data[log_type] = json.load(f)[log_type]
    else:
        print(log_type + " log type not supported")


@blueprint.blueprint.route('/demo', methods=['GET'])
# @jwt_required
def data_endpoint():
    log = request.args.get("log")
    stat = request.args.get("stat")

    if log is None or stat is None:
        return '{"error": "You must specify both a log and stat."}', 400

    global analysis_data
    if analysis_data[log] is not None:
        try:
            r = analysis_data[log][stat]
            return json.dumps(r), 200
        except KeyError:
            return '{"error": "The requested log or stat was not found in the submitted data."}', 400
    else:
        try:
            global analysis_filenames
            with open(analysis_filenames[log], 'r') as f:
                analysis_data[log] = json.load(f)[log]

            r = analysis_data[log][stat]
            return json.dumps(r), 200
        except IOError:
            return '{"error": "No data has been submitted yet and the default demo logs were not found. ' \
                   'Run the \'analyze log\' action from the Bro app."}', 400


@blueprint.blueprint.route('/map', methods=['GET'])
# @jwt_required
def graph_endpoint():
    global netmap
    if netmap is not None:
        return json.dumps(netmap), 200
    else:
        try:
            global netmap_filename
            with open(netmap_filename, 'r') as f:
                netmap = json.load(f)

            return json.dumps(netmap), 200
        except IOError:
            return '{"error": "No netmap has been submitted yet and the default demo logs were not found. ' \
                      'Run the \'build netmap\' action from the Bro app."}', 400
