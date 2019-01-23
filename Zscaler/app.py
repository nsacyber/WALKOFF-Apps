import json
from datetime import datetime
import time
import requests
import logging
from apps import App, action

logger = logging.getLogger(__name__)

class Zscaler(App):
    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.api_key = self.device.get_encrypted_field('api_key')
        self.obfuscated_api_key = self.obfuscate_api_key()
        self.api_username = self.device_fields['username']
        self.api_password = self.device.get_encrypted_field('password')
        self.api_host = self.device_fields['zscaler_pop']
        self.api_base_url = 'https://%s/api/v1/' % (self.api_host)
        self.api_headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache'
        }

    def obfuscate_api_key(self):
        seed = self.api_key
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ''
        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j]) + 2]
        return key, now

    ### Session
    @action
    def create_session(self):
        url = self.api_base_url + 'authenticatedSession'
        key, now = self.obfuscate_api_key()
        data = {
            'apiKey': key,
            'username': self.api_username,
            'password': self.api_password,
            'timestamp': now
        }
        response = requests.post(url, data=json.dumps(data), headers=self.api_headers)
        if response.status_code == 200:
            return response.cookies['JSESSIONID']
        else:
            return  str(datetime.utcnow()), 'Fail'
    
    @action
    def delete_session(self, session):
        headers = self.api_headers
        headers['cookie'] = 'JSESSIONID=%s' % (session)
        url = self.api_base_url + 'authenticatedSession'
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            return 'Successfully logged out'

    ### Configuration status
    @action
    def activate_config(self, session):
        headers = self.api_headers
        headers['cookie'] = 'JSESSIONID=%s' % (session)
        url = self.api_base_url + 'status/activate'
        response = requests.post(url, headers=headers)
        return response.json()
    

    ### URL Categories
    @action
    def url_categories(self, session, category_id):
        headers = self.api_headers
        headers['cookie'] = 'JSESSIONID=%s' % (session)
        url = self.api_base_url + 'urlCategories/%s' % (category_id)
        response = requests.get(url, headers=headers)
        return response.json()
    
    @action
    def url_lookup(self, session, domain_list):
        headers = self.api_headers
        headers['cookie'] = 'JSESSIONID='+session
        print(headers)
        url = self.api_base_url + 'urlLookup'
        data = json.dumps(domain_list)
        response = requests.post(url, data=data, headers=headers)
        print(response.text)
        json_result = response.json()
        return json_result
    
    @action
    def add_to_custom_category(self, session, category_id, domain_list):
        category_info = self.url_categories(session, category_id)
        print(category_info.result['configuredName'])
        data = {
            'configuredName': category_info.result['configuredName'],
            'superCategory': category_info.result['superCategory'],
            'dbCategorizedUrls': domain_list,
            'description': category_info.result['description']
        }
        headers = self.api_headers
        headers['cookie'] = 'JSESSIONID=%s' % (session)
        url = self.api_base_url + 'urlCategories/%s?action=ADD_TO_LIST' % (category_id)
        response = requests.put(url, data=json.dumps(data), headers=headers)
        return response.json()
