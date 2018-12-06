import logging

from apps import App, action
from proxmoxer import ProxmoxAPI

logger = logging.getLogger(__name__)


class Proxmox(App):
    """
       Skeleton example app to build other apps off of
    
       Args:
           app_name (str): Name of the app
           device (list[str]): List of associated device names
           context (dict): Information about the context in which the App is operating
           
    """

    def __init__(self, app_name, device, context):
        App.__init__(self, app_name, device, context)  # Required to call superconstructor
        self.proxmox = ProxmoxAPI(self.host, user=self.device_fields["username"],
                                  password=self.device.get_encrypted_field("password"), verify_ssl=False)

    @action
    def get_all_nodes(self):
        return self.proxmox.nodes.get()

    @action
    def get_all_vms(self):
        nodes_vms = []
        for node in self.proxmox.nodes.get():
            node['vms'] = []
            for vm in self.proxmox.nodes(node['node']).openvz.get():
                node['vms'].append(vm)
            nodes_vms.append(node)


    @action
    def get_all_vms_for_node(self, node_name):
        for node in self.proxmox.nodes.get():

