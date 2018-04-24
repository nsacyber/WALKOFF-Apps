from apps import App, action
import requests
from requests.exceptions import HTTPError
from copy import deepcopy
import logging

logger = logging.getLogger(__name__)


class Vectra(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.url = 'http://{}/api/v2'.format(self.device_fields['url'])
        self.headers = {'Authorization': 'Token {}'.format(self.device.get_encrypted_field('token'))}

    def get_all_results(self, resource, params=None):
        params = params or {}
        response = requests.get('{}/{}'.format(self.url, resource), params=params, headers=self.headers, verify=False).json()
        logger.info('Got Vectra response {}'.format(response))
        results = response['results']
        while response.get('next', False):
            url = response['next']
            response = requests.get(url, headers=self.headers, params=params, verify=False).json()
            results.extend(response.get('results', []))
        return results

    def get_individual_result(self, resource, id):
        response = requests.get('{}/detections/{}'.format(self.url, id), headers=self.headers, verify=False)
        logger.info('Got Vectra response {}'.format(response))
        try:
            response.raise_for_status()
            return response.json(), 'Success'
        except HTTPError:
            return response.json(), 'Error'

    @action
    def get_all_detections(
            self,
            ordering=None,
            reverse_order=False,
            min_id=None,
            max_id=None,
            state=None,
            category=None,
            source_ip=None,
            threat_equals=None,
            min_threat=None,
            certainty_equals=None,
            min_certainty=None,
            last_timestamp=None,
            host_id=None,
            tags=None,
            destination=None,
            proto=None):
        query_params = {}
        if ordering:
            query_params['ordering'] = ordering if not reverse_order else '-{}'.format(ordering)
        if min_id:
            query_params['min_id'] = min_id
        if max_id:
            query_params['max_id'] = max_id
        if state:
            query_params['state'] = state
        if category:
            query_params['category'] = category
        if source_ip:
            query_params['src_ip'] = source_ip
        if threat_equals:
            query_params['t_score'] = threat_equals
        if min_threat:
            query_params['t_score_gte'] = min_threat
        if certainty_equals:
            query_params['c_score'] = certainty_equals
        if min_certainty:
            query_params['c_score_gte'] = min_certainty
        if last_timestamp:
            query_params['last_timestamp'] = last_timestamp
        if host_id:
            query_params['host_id'] = host_id
        if tags:
            query_params['tags'] = ','.join(tags)
        if destination:
            query_params['destination'] = destination
        if proto:
            query_params['proto'] = proto

        return self.get_all_results('detections', params=query_params)

    @action
    def get_detection(self, id):
        return self.get_individual_result('detections', id)

    @action
    def get_all_hosts(
            self,
            ordering=None,
            reverse_order=False,
            min_id=None,
            max_id=None,
            state=None,
            last_source_ip=None,
            threat_equals=None,
            min_threat=None,
            certainty_equals=None,
            min_certainty=None,
            last_detection_timestamp=None,
            tags=None,
            key_asset=None,
            targets_key_asset=None,
            active_traffic=None,
            mac_address=None):
        query_params = {}
        if ordering:
            query_params['ordering'] = ordering if not reverse_order else '-{}'.format(ordering)
        if min_id:
            query_params['min_id'] = min_id
        if max_id:
            query_params['max_id'] = max_id
        if state:
            query_params['state'] = state
        if last_source_ip:
            query_params['last_source'] = last_source_ip
        if threat_equals:
            query_params['t_score'] = threat_equals
        if min_threat:
            query_params['t_score_gte'] = min_threat
        if certainty_equals:
            query_params['c_score'] = certainty_equals
        if min_certainty:
            query_params['c_score_gte'] = min_certainty
        if last_detection_timestamp:
            query_params['last_detection_timestamp'] = last_detection_timestamp
        if tags:
            query_params['tags'] = ','.join(tags)
        if key_asset:
            query_params['key_asset'] = key_asset
        if targets_key_asset:
            query_params['targets_key_asset'] = targets_key_asset
        if active_traffic:
            query_params['active_traffic'] = active_traffic
        if mac_address:
            query_params['mac_address'] = mac_address
        return self.get_all_results('hosts')

    @action
    def get_host(self, id):
        return self.get_individual_result('hosts', id)

    @action
    def set_key_asset(self, id):
        return self.mark_key_asset(id, True)

    @action
    def unset_key_asset(self, id):
        return self.mark_key_asset(id, False)

    def mark_key_asset(self, id, mark):
        headers = deepcopy(self.headers)
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        response = requests.patch('{}/hosts/{}'.format(self.url, id), headers=headers, data='key_asset={}'.format(mark),
                                  verify=False)
        try:
            response.raise_for_status()
            return 'success'
        except HTTPError:
            return 'error', 'Error'
