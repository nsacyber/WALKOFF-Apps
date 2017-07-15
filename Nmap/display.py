from core.case.callbacks import FunctionExecutionSuccess
import json

last_results = None


@FunctionExecutionSuccess.connect
def record_nmap_results(sender, **kwargs):
    global last_results
    if sender.app == 'Nmap' and sender.action == 'run scan':
        last_results = json.loads(kwargs['data'])['result']['result']


def load(*args, **kwargs):
    if last_results is not None:
        return {'results': last_results}
    else:
        return {}
