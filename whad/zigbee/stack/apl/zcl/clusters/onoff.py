from whad.zigbee.stack.apl.zcl import ZCLCluster, ZCLClientCluster, ZCLServerCluster
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode

# TODO: Find a wrapper to access server and client clusters easily ?

class OnOffClient(ZCLClientCluster):

    def __init__(self):
        super().__init__(cluster_id=0x0006)

    @ZCLCluster.command_generate(0x00, "Off")
    def off(self):
        command = b""
        self.send_command(command)
        status = self.wait_response()
        return status == 0

    @ZCLCluster.command_generate(0x01, "On")
    def on(self):
        command = b""
        self.send_command(command)
        status = self.wait_response()
        return status == 0

    @ZCLCluster.command_generate(0x02, "Toggle")
    def toggle(self):
        command = b""
        self.send_command(command)
        status = self.wait_response()
        return status == 0

class OnOffServer(ZCLServerCluster):

    OnOff: (0x0000, ["read", "report", "scene"]) = 0
    GlobalSceneControl: (0x4000, ["read"]) = 1
    OnTime: (0x4001, ["read", "write"]) = 0
    OffWaitTime: (0x4002, ["read", "write"]) = 0


    @ZCLCluster.command_receive(0x00, "Off")
    def on_off(self, command):
        self.OnOff = 0
        # default response ?

    @ZCLCluster.command_receive(0x01, "On")
    def on_off(self, command):
        self.OnOff = 1
        # default response ?

    @ZCLCluster.command_receive(0x02, "Toggle")
    def on_off(self, command):
        self.OnOff = 1 - self.OnOff
        # default response ?
