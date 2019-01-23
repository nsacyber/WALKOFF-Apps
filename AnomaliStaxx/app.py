import logging
from apps import App, action
import json
import requests


requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)


class AnomaliStaxx(App):

    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.base_url = 'https://%s:%s/api/v1/' % (self.device_fields['staxx_address'], self.device_fields['staxx_port'])
        self.headers = {'content-type': 'application/json'}
        self.staxx_username = self.device_fields['username']
        self.staxx_password = self.device.get_encrypted_field('password')
        self.verify_certificate = self.device_fields['verify_certificate']

    def authenticate(self, user, password):
        url = self.base_url + 'login'
        data  = json.dumps({'username':user, 'password':password})
        request = requests.post(url, data=data, headers=self.headers, verify=False)
        if request.status_code == 200:
            return request.json()['token_id']

    @action
    def export_indicators(self, search=None):
        token = self.authenticate(self.staxx_username, self.staxx_password)
        url = self.base_url + 'intelligence'
        data = json.dumps({'token':token, 'query':search, 'type':'json'})
        response = requests.post(url, data=data, headers=self.headers, verify=self.verify_certificate)
        if response.status_code == 200:
            return response.json()