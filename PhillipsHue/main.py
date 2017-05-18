from server import appdevice
import requests


class Main(appdevice.App):
    """
    Controls the Phillips Hue Light
    """
    def __init__(self, name=None, device=None):
        appdevice.App.__init__(self, name, device)
        device = self.devices[device] if device in self.devices else None
        if device is None:
            self.ip = ""
            self.username = ""
        else:
            self.ip = device.ip
            self.username = device.username
        self.baseURL = "http://" + self.ip + "/api/" + self.username
        self.headers = {'content-type': 'application/json'}

    def getLights(self, *args, **kwargs):
        """ Gets all the connected lights
        """
        url = self.baseURL + "/lights"
        r = requests.get(url)
        return r.text

    def getLightInfo(self, *args, **kwargs):
        """ Gets specific light information
        """
        url = self.baseURL + "/lights/" + kwargs["light"]
        r = requests.get(url)
        return r.text

    def turnLightOn(self, *args, **kwargs):
        """ Turns a light on
        """
        url = self.baseURL + "/lights/" + kwargs["light"] + "/state"
        body = {"on": "true"}
        r = requests.put(url, json=body)
        return r.text

    def turnLightOff(self, *args, **kwargs):
        """ Turns a light off
        """
        url = self.baseURL + "/lights/" + kwargs["light"] + "/state"
        body = {"on": "false"}
        r = requests.put(url, json=body)
        return r.text

    def shutdown(self):
        return
