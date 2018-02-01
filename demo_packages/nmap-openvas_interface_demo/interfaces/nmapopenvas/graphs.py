from interfaces import dispatcher, AppBlueprint
from walkoff.events import WalkoffEvent
from flask import Blueprint, jsonify
import json

blueprint = AppBlueprint(blueprint=Blueprint('NOVAS_Demo', __name__))

latest_graph = "WalkoffDemoGraph.json"


@dispatcher.on_app_actions('Nmap', actions=['graph from results'],
                           events=WalkoffEvent.ActionExecutionSuccess)
def get_latest_graph(data):
    global latest_graph
    latest_graph = data['arguments'][3]['value']


@blueprint.blueprint.route('/demo', methods=['GET'])
def read_and_send_graph():
    try:
        global latest_graph
        with open(latest_graph) as f:
            r = jsonify(json.load(f))

        return r, 200
    except IOError:
        return None, 461
