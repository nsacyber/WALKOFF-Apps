from apps import Event, AppBlueprint
from flask import Blueprint, request
import logging

blueprint = AppBlueprint(blueprint=Blueprint('OpenVASEvents', __name__))
pull_down = Event('pull_down')

logger = logging.getLogger(__name__)


@blueprint.blueprint.route('/pull_down', methods=['POST'])
def resume():
    print("in events.py")
    data = request.get_json()
    print("Received data")
    print(data)
    pull_down.trigger(data)
    # pull_down.trigger("hi")
    return 'Success'

