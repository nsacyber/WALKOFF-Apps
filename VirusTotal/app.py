import logging
from apps import App, action
import requests

logger = logging.getLogger(__name__)

class VirusTotal(App):
    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.proxy = None
        if (self.device_fields['proxy_address'] and self.device_fields['proxy_port']):
            self.proxy = {
                        'http': 'http://%s:%s' % (self.device_fields['proxy_address'], self.device_fields['proxy_port']),
                        'https': 'https://%s:%s' % (self.device_fields['proxy_address'], self.device_fields['proxy_port']),
                    }
        self.api_key = self.device.get_encrypted_field('api_key')

    @action
    def search_hash(self, file_hash):
        url = self.base_url + 'file/report'
        params = {'apikey': self.api_key, 'resource': file_hash}
        response = requests.get(url, params=params, proxies=self.proxy).json()
        return response

    @action
    def search_ip(self, ip):
        url = self.base_url + 'ip-address/report'
        params = {'apikey': self.api_key, 'ip': ip}
        response = requests.get(url, params=params, proxies=self.proxy).json()
        return response

    @action
    def search_domain(self, domain):
        url = self.base_url + 'domain/report'
        params = {'apikey': self.api_key, 'domain': domain}
        response = requests.get(url, params=params, proxies=self.proxy).json()
        return response

    @action
    def scan_url(self, url):
        url = self.base_url + 'url/scan'
        params = {'apikey': self.api_key, 'url': url}
        response = requests.get(url, params=params, proxies=self.proxy).json()
        return response
