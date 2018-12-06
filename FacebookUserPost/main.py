from apps import App, action
import requests


class Main(App):

    def __init__(self, name, device, context):
        self.user_id = self.device_fields['username']
        self.user_access_token = self.device.get_encrypted_field('password')
        App.__init__(self, name, device, context)

    @action
    def post_to_user_wall(self, message):
        msg = message.replace(" ", "+")
        url = ('https://graph.facebook.com/v2.9/' + self.user_id + '/feed?'
               'message=' + msg + '&access_token=' + self.device.get_encrypted_field('token'))
        return (requests.post(url, verify=False)).text
