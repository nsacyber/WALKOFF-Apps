import logging
from apps import App, action
import subprocess
from OTXv2 import InvalidAPIKey
from six.moves import urllib_error

logger = logging.getLogger(__name__)


class AlienVault(App):

    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.api_key = self.device_fields['key']

    @action
    def download_indicators(self, directory=None, proxy=None):
        sbase_args = ["./apps/AlienVault/signature-base/threatintel/get-otx-iocs.py"]
        if directory is not None:
            sbase_args += ["-o", directory]
        else:
            sbase_args += ["-o", "./apps/AlienVault/signature-base/iocs"]
        if proxy is not None:
            sbase_args += ["-p", proxy]

        try:
            subprocess.call(sbase_args)
            return True, "Success"
        except InvalidAPIKey:
            return "Ensure your API key was set correctly.", "InvalidKey"
        except urllib_error.URLError:
            return "Error in URL resolution to OTX.", "URLError"
        except IOError as e:
            return e, "FileError"
