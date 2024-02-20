from whad.zigbee.stack.apl.zcl import ZCLCluster, ZCLClientCluster, ZCLClusterConfiguration
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, ZLLScanRequest, ZLLIdentifyRequest, \
    ZLLDeviceInformationRequest, ZLLResetToFactoryNewRequest, ZLLNetworkJoinRouterRequest, ZLLNetworkStartRequest
from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.zigbee.profile.network import Network
from whad.zigbee.crypto import TouchlinkKeyManager

from struct import pack, unpack
from time import time
from random import randint

class ZCLTouchLinkClient(ZCLClientCluster):

    def __init__(self):
        self.transaction_id = None
        super().__init__(
            cluster_id=0x1000,
            default_configuration=ZCLClusterConfiguration(
                destination_address=0xFFFF,
                destination_pan_id =0xFFFF,
                interpan=True,
                disable_default_response=True
            )
        )

    def scan(self, channels = [11, 15, 20, 25], link_initiator=True, address_assignment=True, factory_new=True):
        """
        Perform a touchlink scan and return detected networks.
        """
        # Select the channel page 0
        mac_layer = self.application.manager.get_layer('mac')
        nwk_layer = self.application.manager.get_layer('nwk')

        mac_layer.set_channel_page(0)

        for channel in channels:
            # Go to touchlink channel
            mac_layer.set_channel(channel)
            # Send a scan request and wait for response
            scan_response = self.scan_request(
                link_initiator = link_initiator,
                address_assignment = address_assignment,
                factory_new = factory_new
            )
            if scan_response is not None:
                pdu, source = scan_response
                print("Source", source)
                pdu.show()
                a = self.reset_to_factory_new(destination_address=source, transaction_id=pdu.inter_pan_transaction_id)
                print("a", a)
                '''
                network_address = randint(2, 0xFFF0)
                resp = self.network_join_router_request(
                                                transaction_id=pdu.inter_pan_transaction_id,
                                                response_id=pdu.response_id,
                                                destination_address=source,
                                                logical_channel=0,
                                                pan_id=pdu.pan_id,
                                                extended_pan_id=pdu.pan_id_ext,
                                                network_address=network_address
                )
                '''

                return network_address


    @ZCLCluster.command_generate(0x00, "ScanRequest")
    def scan_request(self, transaction_id=None, link_initiator=True, address_assignment=True, factory_new=True):
        """
        Trigger a scan request.
        """
        # Get a new transaction ID if needed.
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        # Get the local node descriptor
        node_descriptor = self.application.manager.get_application_by_name("zdo").configuration.get("configNodeDescriptor")
        # Build and send a Scan Request
        command = ZLLScanRequest(
            inter_pan_transaction_id=transaction_id,
            rx_on_when_idle=int(node_descriptor.receiver_on_when_idle),
            logical_type=int(node_descriptor.logical_type),
            link_initiator=int(link_initiator),
            address_assignment=int(address_assignment),
            factory_new=int(factory_new)
        )

        self.send_command(command)
        # Return the received response (if any)
        return self.wait_response()

    @ZCLCluster.command_receive(0x01, "ScanResponse")
    def on_scan_response(self, command, source_address):
        """
        Process a scan response.
        """
        self.push_response(
            (command, source_address),
            command.inter_pan_transaction_id
        )




    @ZCLCluster.command_generate(0x02, "DeviceInformationRequest")
    def device_information_request(self,transaction_id=None, start_index=0, destination_address=None):
        """
        Performs a Device Information request.
        """
        # Get a new transaction ID if needed.
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        print(transaction_id)
        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        command = ZLLDeviceInformationRequest(inter_pan_transaction_id=transaction_id, start_index=start_index)
        command.show()
        self.send_command(command)
        return self.wait_response()

    @ZCLCluster.command_generate(0x06, "IdentifyRequest")
    def identify_request(self,transaction_id=None, identify_duration=1, destination_address=None):
        """
        Performs an Identify request.
        """
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        command = ZLLIdentifyRequest(inter_pan_transaction_id=transaction_id, identify_duration=identify_duration)
        self.send_command(command)

    @ZCLCluster.command_generate(0x07, "ResetToFactoryNew")
    def reset_to_factory_new(self,transaction_id=None, destination_address=None):
        """
        Performs a reset to factory new.
        """
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )
        command = ZLLResetToFactoryNewRequest(inter_pan_transaction_id=transaction_id)
        self.send_command(command)

    @ZCLCluster.command_generate(0x12, "NetworkJoinRouterRequest")
    def network_join_router_request(
                                    self,
                                    transaction_id=None,
                                    response_id=None,
                                    destination_address=None,
                                    key_index=4,
                                    network_update_id=0,
                                    key=bytes.fromhex("01020102030403040506050607080708")[::-1],
                                    logical_channel=25,
                                    pan_id=0x1234,
                                    extended_pan_id=0x0102030405060708,
                                    network_address=0x0001
    ):
        """
        Performs a network join router request.
        """
        # Get a new transaction ID if needed.
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        # Configure the transmission parameters
        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        # Encrypt the key
        encrypted_key = TouchlinkKeyManager(
            unencrypted_key=key,
            response_id=response_id,
            transaction_id=transaction_id,
            key_index=key_index
        ).encrypted_key

        command = ZLLNetworkJoinRouterRequest(
            inter_pan_transaction_id=transaction_id,
            pan_id_ext=extended_pan_id,
            key_index=key_index,
            encrypted_network_key=encrypted_key,
            network_update_id=network_update_id,
            channel=logical_channel,
            pan_id=pan_id,
            network_address=network_address
        )

        self.send_command(command)
        return self.wait_response()

    @ZCLCluster.command_receive(0x13, "NetworkJoinRouterResponse")
    def on_network_join_router_response(self, command, source_address):
        """
        Process a network join router response.
        """
        command.show()
        self.push_response(
            (command, source_address),
            command.inter_pan_transaction_id
        )


    @ZCLCluster.command_generate(0x10, "NetworkStartRequest")
    def network_start_router_request(
                                    self,
                                    transaction_id=None,
                                    response_id=None,
                                    destination_address=None,
                                    key_index=4,
                                    key=bytes.fromhex("11223344556677881122334455667788"),
                                    logical_channel=25,
                                    pan_id=0x1234,
                                    extended_pan_id=0x0102030405060708,
                                    network_address=0x0001,
                                    initiator_network_address=0x0002,
                                    initiator_ieee_address=None
    ):
        """
        Performs a network start request.
        """
        # Get a new transaction ID if needed.
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        if initiator_ieee_address is None:
            initiator_ieee_address = unpack('<Q',
                pack(">Q",
                    self.application.manager.get_layer("nwk").database.get("nwkIeeeAddress")
                )
            )[0]

        # Configure the transmission parameters
        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        # Encrypt the key
        encrypted_key = TouchlinkKeyManager(
            unencrypted_key=key,
            response_id=response_id,
            transaction_id=transaction_id,
            key_index=key_index
        ).encrypted_key

        command = ZLLNetworkStartRequest(
            inter_pan_transaction_id=transaction_id,
            pan_id_ext=extended_pan_id,
            key_index=key_index,
            encrypted_network_key=encrypted_key,
            channel=logical_channel,
            pan_id=pan_id,
            network_address=network_address,
            initiator_ieee_address=initiator_ieee_address,
            initiator_network_address=initiator_network_address,
        )

        self.send_command(command)
        return self.wait_response()


    @ZCLCluster.command_receive(0x03, "DeviceInformationResponse")
    def on_device_information_response(self, command, source_address):
        """
        Process a device information response.
        """
        self.push_response(
            (command, source_address),
            command.inter_pan_transaction_id
        )

    @ZCLCluster.command_receive(0x11, "NetworkStartResponse")
    def on_network_start_response(self, command, source_address):
        """
        Process a network start response.
        """
        self.push_response(
            (command, source_address),
            command.inter_pan_transaction_id
        )

    def push_response(self, response, transaction_id):
        """
        Adding a response to the pending responses.
        """
        # Check if a pending response is expected
        if transaction_id in self.pending_responses:
            # Add the response
            self.pending_responses[transaction_id] = response

    def wait_response(self, transaction=None, timeout=1):
        """
        Wait for the response associated to a specific transaction (default: transaction id).
        """
        # if transaction not provided, use the last transaction by default
        if transaction is None:
            transaction = self.transaction_id

        # Clear the entry associated to the provided transaction in pending responses dictionnary
        self.pending_responses[transaction] = None

        start = time()
        while self.pending_responses[transaction] is None and time() - start < timeout:
            pass
        # If we got a response return it, otherwise a timeout occured and we return None
        if self.pending_responses[transaction] is not None:
            return_value = self.pending_responses[transaction]
        else:
            return_value = None
        del self.pending_responses[transaction]
        return return_value
