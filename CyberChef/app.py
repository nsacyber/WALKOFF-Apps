import logging
import json
import tempfile
import shutil
import os
from apps import App, action
from Naked.toolshed.shell import muterun_js

logger = logging.getLogger(__name__)

class CyberChefApp(App):
    """
       Runs operations from GCHQ Cyberchef
       https://github.com/gchq/CyberChef

       Args:
           name (str): Name of the app
           device (list[str]): List of associated device names

    """

    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)  # Required to call superconstructor


    def setupOpTemporaryCopy(self, value, action, args):
        operationsScript = """
            p1 = module.exports.bake("{0}", [{{ "op":"{1}","args":{2} }}] );
            Promise.all([p1]).then(values => {{
                console.log(JSON.stringify(values[0]));
            }});
        """.format(value, action, args)
        temppath = os.path.dirname(self.device_fields["CyberChefPath"])
        tf = tempfile.NamedTemporaryFile(mode="r+b", dir=temppath, prefix="__", suffix=".tmp")
        with open(self.device_fields["CyberChefPath"], "r+b") as f:
            shutil.copyfileobj(f, tf)

        tf.write(operationsScript.encode())
        # Rewind to beginning, otherwise Windows errors
        tf.seek(0)
        return tf

    def setupWorkflowTemporaryCopy(self, value, workflow):
        workflowScript = """
            p1 = module.exports.bake("{0}", {1} );
            Promise.all([p1]).then(values => {{
                console.log(JSON.stringify(values[0]));
            }});
        """.format(value, workflow)
        temppath = os.path.dirname(self.device_fields["CyberChefPath"])
        tf = tempfile.NamedTemporaryFile(mode="r+b", dir=temppath, prefix="__", suffix=".tmp")
        with open(self.device_fields["CyberChefPath"], "r+b") as f:
            shutil.copyfileobj(f, tf)

        tf.write(workflowScript.encode())
        # Rewind to beginning, otherwise Windows errors
        tf.seek(0)
        return tf

    def handleOutput(self, response):
        if response.exitcode == 0:
            r = json.loads(response.stdout.decode())
            #If the script executed but the workflow failed
            if r["error"] ==  True:
                return response.stdout, "Error"

            result = r["result"]
            if r["type"] == "number":
                result = float(result)
                return result, "SuccessNumber"
            return result, "Success"
        else:
            #If the script failed to execute
            return response.stderr, "Error"

    @action
    def run_cyberchef_function(self, input, action, args):
        #Javascript that ties together the execution

        with self.setupOpTemporaryCopy(input, action, args) as tf:
            response = muterun_js(tf.name)

        return self.handleOutput(response)


    @action
    def run_cyberchef_workflow(self, input, workflow):
        with self.setupWorkflowTemporaryCopy(input, workflow) as tf:
            response = muterun_js(tf.name)

        return self.handleOutput(response)

    def shutdown(self):
        pass



