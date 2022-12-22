from whad.zigbee.stack.apl.zcl import ZCLCluster
from whad.zigbee.stack.mac.constants import MACAddressMode
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, ZLLScanRequest
from random import randint
# TODO: old version, refactoring needed

'''
class ZCLTouchLink(ZCLCluster):
    def __init__(self):
        super().__init__(cluster_id=0x1000)

    def register_commands(self):
        self.commands.add_command(0x00, "ScanRequest", generate_callback=self.scan_request, receive_callback=None)
        self.commands.add_command(0x01, "ScanResponse", generate_callback=None, receive_callback=self.on_scan_response)

    def scan_request(self, transaction_id=randint(0, 0xFFFFFFFF), link_initiator=True, address_assignment=True, factory_new=True):
        node_descriptor = self.application.manager.get_application_by_name("zdo").configuration.get("configNodeDescriptor")

        command = ZLLScanRequest(
            inter_pan_transaction_id=transaction_id,
            rx_on_when_idle=int(node_descriptor.receiver_on_when_idle),
            logical_type=int(node_descriptor.logical_type),
            link_initiator=link_initiator,
            address_assignment=address_assignment,
            factory_new=factory_new
        )

        return self.send_command(0x00, command)

    def on_scan_response(self, payload, transaction=None, no_response=True):
        payload.show()

    def send_command(self, command_identifier, command, transaction=None,  disable_default_response=True):
        if transaction is None:
            transaction = ZCLCluster.zcl_transaction_counter
            ZCLCluster.zcl_transaction_counter += 1

        asdu = ZigbeeZLLCommissioningCluster(
                zcl_frametype=1,
                direction=0,
                command_identifier=command_identifier,
                transaction_sequence=transaction,
                disable_default_response=disable_default_response
        ) / command

        return self.send_interpan_data(asdu, asdu_handle=0, source_address_mode=MACAddressMode.EXTENDED, destination_pan_id=0xFFFF, destination_address=0xFFFF)

    def on_interpan_data(self, asdu,destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        command_identifier = asdu.command_identifier

        try:
            command = self.commands.get_command(command_identifier)
            command.receive_callback(asdu[ZigbeeZLLCommissioningCluster].payload, transaction=asdu.transaction_sequence, no_response=asdu.disable_default_response)

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))
'''
