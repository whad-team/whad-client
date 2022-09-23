from whad.zigbee.stack.apl.zcl import ZCLCluster
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode

class ZCLOnOff(ZCLCluster):
    attribute1: (0x0000, ["read"])
    attribute2: (0x0001, ["read", "write"])

    def __init__(self):
        super().__init__(cluster_id=0x0006)

    @ZCLCluster.command_generate(0x01, "On")
    def on(self, address):
        return self.send_command(0x01, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    @ZCLCluster.command_generate(0x00, "Off")
    def off(self, address):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    @ZCLCluster.command_receive(0x00, "Off")
    def on_off(self):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

a = ZCLOnOff()
'''
class ZCLOnOff(ZCLCluster):
    def __init__(self):
        super().__init__(cluster_id=0x0006)

    def register_attributes(self):
        self.attributes.add_attribute(0x0000, "toto", ["read"])

    def register_commands(self):
        self.commands.add_command(0x00, "Off", generate_callback=self.off, receive_callback=None)
        self.commands.add_command(0x01, "On", generate_callback=self.on, receive_callback=None)
        self.commands.add_command(0x02, "Toggle", generate_callback=self.toggle, receive_callback=None)

    def on(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x01, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    def off(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    def toggle(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x02, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)
'''
