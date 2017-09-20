import logging
from apps import App, action
import requests
from requests.exceptions import Timeout
import json
from core.config.paths import certificate_path

logger = logging.getLogger(__name__)


class Unauthorized(Exception):
    pass


class UnknownResponse(Exception):
    pass


class NotConnected(Exception):
    pass


DEFAULT_TIMEOUT = 2


class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.is_connected = False
        self.headers = None
        self.refresh_token = None
        self.walkoff_address = self.get_device().ip
        port = self.get_device().port
        if port:
            self.walkoff_address += ':{}'.format(port)
        self.is_https = self.walkoff_address.startswith('https')

    @action
    def connect(self, timeout=DEFAULT_TIMEOUT):
        username = self.get_device().username
        try:
            response = self._request('post', '/api/auth', timeout,
                                     data=dict(username=username, password=self.get_device().get_password()),
                                     follow_redirects=True)
        except Timeout:
            return 'Connection timed out', 'TimedOut'

        status_code = response.status_code
        if status_code == 404:
            return 'Could not locate Walkoff Instance', 'WalkoffNotFound'
        elif status_code == 401:
            return 'Invalid login', 'AuthenticationError'
        elif status_code == 201:
            response = json.loads(response.get_data(as_text=True))
            self.refresh_token = response['refresh_token']
            self.reset_authorization(response['access_token'])
            self.is_connected = True
            return 'Success'
        else:
            return 'Unknown response {}'.format(status_code), 'UnknownResponse'

    @action
    def trigger(self, names=None, inputs=None, data=None, tags=None, timeout=DEFAULT_TIMEOUT):
        trigger_data = {}
        if names:
            trigger_data['names'] = names
        if inputs:
            trigger_data['inputs'] = inputs
        if data:
            trigger_data['data'] = data
        if tags:
            trigger_data['tags'] = tags

        return self.standard_request('post', '/api/triggers/execute', timeout, headers=self.headers, data=data)

    @action
    def get_workflow_results(self, timeout=DEFAULT_TIMEOUT):
        return self.standard_request('get', '/workflowresults/all', timeout, headers=self.headers)

    def standard_request(self, method, address, timeout, headers=None, data=None, **kwargs):
        try:
            return self.request_with_refresh(method, address, timeout, headers=headers, data=data, **kwargs)
        except Timeout:
            return 'Connection timed out', 'TimedOut'
        except Unauthorized:
            return 'Unauthorized Credentials', 'Unauthorized'
        except NotConnected:
            return 'Not connected to walkoff', 'NotConnected'
        except UnknownResponse:
            return 'Unknown error occurred', 'UnknownResponse'

    def _format_request_args(self, address, timeout, headers=None, data=None, **kwargs):
        address = '{0}{1}'.format(self.walkoff_address, address)
        args = kwargs
        args['timeout'] = timeout
        if not (self.headers is None and headers is None):
            args['headers'] = headers if headers is not None else self.headers
        if data is not None:
            args['data'] = json.dumps(data)
        if self.is_https:
            args['verify'] = certificate_path
        return address, args

    def _request(self, method, address, timeout, headers=None, data=None, **kwargs):
        address, args = self._format_request_args(address, timeout, headers, data, **kwargs)
        if method == 'put':
            return requests.put(address, **args)
        elif method == 'post':
            return requests.post(address, **args)
        elif method == 'get':
            return requests.get(address, **args)
        elif method == 'delete':
            return requests.delete(address, **args)

    def request_with_refresh(self, method, address, timeout, headers=None, data=None, **kwargs):
        if self.is_connected:
            response = self._request(method, address, timeout, headers, data, **kwargs)
            if response.status_code != 401:
                return response
            else:
                self.refresh_token(timeout)
                response = self._request(method, address, timeout, headers, data, **kwargs)
                if response.status_code == 401:
                    self.is_connected = False
                    raise Unauthorized
                else:
                    return response
        else:
            raise NotConnected

    def refresh_token(self, timeout):
        headers = {'Authorization': 'Bearer {}'.format(self.refresh_token)}
        response = self._post('/api/auth/refresh', timeout, headers=headers)
        if response.status_code == 401:
            raise Unauthorized
        elif response.status_code == 201:
            key = json.loads(response.get_data(as_text=True))
            self.reset_authorization(key['access_token'])
        else:
            raise UnknownResponse

    def reset_authorization(self, token):
        self.headers = {'Authorization': 'Bearer {}'.format(token)}

    def shutdown(self):
        # logout
        pass
