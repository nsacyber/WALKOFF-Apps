from apps import App, action
import requests
from requests.exceptions import HTTPError
from copy import deepcopy
from datetime import datetime, timedelta


def timestamp_to_datetime(time):
    return datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%fZ')


class Cylance(App):

    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.url = '{}/api/v1'.format(self.device_fields['url'])
        self.token_expiration_time = datetime.utcnow()
        self.reauthenticate_safety_time = timedelta(seconds=30)
        self.headers = {}

    def connect(self):
        response = requests.get(
            '{}/token/get'.format(self.url),
            json={'username': self.device_fields['api_key'], 'password': self.device.get_encrypted_field('password')})
        response.raise_for_status()
        response = response.json()
        token = response['access_token']
        self.token_expiration_time = timestamp_to_datetime(token['expires_at'])
        self.headers = {'Authorization': 'Bearer {}'.format(token['access_token'])}

    def call_cylance(self, resource, operation, data_field=True, **kwargs):
        if datetime.utcnow() - self.token_expiration_time < self.reauthenticate_safety_time:
            try:
                self.connect()
            except HTTPError:
                return 'Could not reauthenticate', 'ConnectionError'
        url = '{}/{}/{}'.format(self.url, resource, operation)
        response = requests.post(url, headers=self.headers, **kwargs)
        try:
            response.raise_for_status()
            return response.json()['data'] if data_field else response.json()
        except HTTPError:
            return response.json(), 'Error'

    @action
    def get_all_threats(self):
        return self.call_cylance('threat', 'get')

    @action
    def get_threat_details(self, sha256):
        return self.call_cylance('threatdetail', 'get', json={'sha256': sha256})

    @action
    def get_all_devices(self):
        return self.call_cylance('device', 'get'.format(self.url))

    @action
    def delete_device(self, serial_number):
        return self.call_cylance('device', 'delete', json={'serial_number': serial_number})

    @action
    def get_threats_for_device(self, serial_number):
        return self.call_cylance('devicethreat', 'get', json={'serial_number': serial_number})

    @action
    def update_threat_for_device(self, serial_number, sha256, quarantine_status):
        data = {'serial_number': serial_number, 'sha256': sha256, 'quarantine_status': quarantine_status}
        return self.call_cylance('devicethreat', 'update', json=data)

    @action
    def get_devices_for_threat(self, sha256):
        return self.call_cylance('threatdevice', 'get', json={'sha256': sha256})

    @action
    def get_all_zones(self):
        return self.call_cylance('zone', 'get', data_field=False)

    @action
    def create_zone(self, zone_name, policy_id=None, zone_criticality='Normal'):
        data = {'zone_name': zone_name, 'policy_id': policy_id, 'zone_criticality': zone_criticality}
        response = self.call_cylance('zone', 'create', data_field=False, json=data)
        if isinstance(response, tuple):
            return response
        return response[0]['zone_id']

    @action
    def update_zone(self,
            zone_id,
            zone_name,
            policy_id=None,
            zone_criticality='Normal',
            apply_policy_change_to_devices=False):
        data = {
            'zone_id': zone_id,
            'zone_name': zone_name,
            'zone_criticality': zone_criticality,
            'apply_policy_change_to_devices': apply_policy_change_to_devices}
        if policy_id:
            data['policy_id'] = policy_id
        response = self.call_cylance('zone', 'create', data_field=False, json=data)
        if isinstance(response, tuple):
            return response
        return response[0]['zone_id']

    @action
    def get_all_policies(self):
        return self.call_cylance('policy', 'get', data_field=False)

    @action
    def get_policy_detail(self, policy_id=None, policy_name=None):
        data = {}
        if policy_id:
            data['policy_id'] = policy_id
        if policy_name:
            data['policy_name'] = policy_name
        return self.call_cylance('policydetail', 'get', data_field=False, json=data)
