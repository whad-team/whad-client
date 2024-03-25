from whad.zigbee.stack.apl.zcl import ZCLCluster, ZCLClientCluster, ZCLServerCluster

class OnOffClient(ZCLClientCluster):
    """
    Zigbee Cluster Library OnOff Client Cluster.
    """
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
    """
    Zigbee Cluster Library OnOff Server Cluster.
    """
    OnOff: (0x0000, ["read", "report", "scene"]) = 0
    GlobalSceneControl: (0x4000, ["read"]) = 1
    OnTime: (0x4001, ["read", "write"]) = 0
    OffWaitTime: (0x4002, ["read", "write"]) = 0

    def __init__(self):
        super().__init__(cluster_id=0x0006)


    @ZCLCluster.command_receive(0x00, "Off")
    def on_off(self, command):
        self.OnOff = 0
        print("[i] Off")
        # default response ?

    @ZCLCluster.command_receive(0x01, "On")
    def on_on(self, command):
        self.OnOff = 1
        print("[i] On")
        # default response ?

    @ZCLCluster.command_receive(0x02, "Toggle")
    def on_toggle(self, command):
        self.OnOff = 1 - self.OnOff
        print("[i] Toggle")
        # default response ?
