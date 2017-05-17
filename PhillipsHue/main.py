from server import appDevice
import requests

# Controls the Phillips Hue Light

class Main(appDevice.App):
    def __init__(self, name=None, device=None):
        appDevice.App.__init__(self, name, device)
        self.ip = ""
        self.username = ""
        self.baseURL = "http://" + self.ip + "/api/" + self.username

    #Gets all the connected lights
    def getLights(self, *args, **kwargs):
        url = self.baseURL + "/lights"
        r = requests.get(url)
        return r.text

    #Gets specific light information
    def getLightInfo(self, *args, **kwargs):
        url = self.baseURL + "/lights/" + kwargs["light"]
        r = requests.get(url)
        return r.text

    def turnLightOn(self, *args, **kwargs):
        url = self.baseURL + "/lights/" + kwargs["light"] + "/state"
        body =  {"on":"true"}
        r = requests.put(url)
        return r.text

    def turnLightOff(self, *args, **kwargs):
        url = self.baseURL + "/lights/" + kwargs["light"] + "/state"
        body = {"on": "false"}
        r = requests.put(url)
        return r.text

    def shutdown(self):
        # print("SHUTTING DOWN")
        return
