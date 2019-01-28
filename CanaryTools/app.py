import time
import logging
import canarytools
import requests
from apps import App, action

logger = logging.getLogger(__name__)

class CanaryTools(App):
    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.api_key = self.device.get_encrypted_field('api_key')
        self.console_domain = self.device_fields['console_domain']
        self.console = canarytools.Console(domain=self.console_domain, api_key=self.api_key)

    @action
    def list_all_tokens(self):
        return [token for token in self.console.tokens.all()]
    
    @action
    def list_all_token_ids(self):
        return [token.canarytoken for token in self.console.tokens.all()]

    @action
    def get_token(self, canarytoken):
        return self.console.tokens.get_token(canarytoken=canarytoken)

    @action
    def enable_token(self, canarytoken):
        token = self.console.tokens.get_token(canarytoken=canarytoken)
        token.enable()
        return 'Success'

    @action
    def disable_token(self, canarytoken):
        token = self.console.tokens.get_token(canarytoken=canarytoken)
        token.disable()
        return 'Success'

    @action
    def delete_token(self, canarytoken):
        token = self.console.tokens.get_token(canarytoken=canarytoken)
        token.delete()
        return 'Success'

    @action
    def download_token(self, canarytoken, path):
        session = requests.session()
        session.params = {'auth_token': self.api_key}
        download_url = 'https://%s.canary.tools/api/v1/canarytoken/download?canarytoken=%s' % (self.console_domain, canarytoken)
        response = requests.session.get(download_url)
        if response.status_code == 200:
            with open(path, 'wb') as f:
                f.write(response.content)
            return 'Success'
        else:
            return 'Failed'

    @action
    def create_token(self, memo, kind, web_image=None, cloned_web=None, mimetype=None):
        token = self.console.tokens.create(memo, kind, web_image, cloned_web, mimetype)
        return token.canarytoken