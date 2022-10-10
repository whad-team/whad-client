from whad.zigbee.stack.apl.zcl import ZCLCluster, ZCLClientCluster
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode

class ZCLOnOff(ZCLClientCluster):
    attribute1: (0x0000, ["read"]) = 12
    attribute2: (0x0001, ["read", "write"]) = "coucou"

    def __init__(self):
        super().__init__(cluster_id=0x0006)

    @ZCLCluster.command_generate(0x00, "Off")
    def off(self):
        command = b""
        self.send_command(command)

    @ZCLCluster.command_generate(0x01, "On")
    def on(self):
        command = b""
        self.send_command(command)

    @ZCLCluster.command_generate(0x02, "Toggle")
    def toggle(self):
        command = b""
        self.send_command(command)


    '''
    @ZCLCluster.command_generate(0x00, "Off")
    def off(self, address):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    @ZCLCluster.command_receive(0x00, "Off")
    def on_off(self):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    @ZCLCluster.command_generate(0x02, "Toggle")
    def toggle(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x02, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)
    '''
