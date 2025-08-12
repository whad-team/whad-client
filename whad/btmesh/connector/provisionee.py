"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

# Add arguments to connector for models/states

from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.connector.node import BTMeshNode

from whad.btmesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
)
from whad.btmesh.stack.network import NetworkLayer

from whad.btmesh.profile import BaseMeshProfile
from whad.scapy.layers.btmesh import (
    BTMesh_Unprovisioned_Device_Beacon,
    EIR_Hdr,
    EIR_PB_ADV_PDU,
    BTMesh_Obfuscated_Network_PDU,
    EIR_BTMesh_Beacon,
)
from whad.btmesh.stack.constants import INPUT_OOB_AUTH, OUTPUT_OOB_AUTH

from scapy.layers.bluetooth4LE import BTLE_ADV_NONCONN_IND, BTLE_ADV


from threading import Event, Thread
from time import sleep
from uuid import UUID


class Provisionee(BTMeshNode):
    def __init__(
        self,
        device,
        profile=None,
        prov_stack=PBAdvBearerLayer,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        dev_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=0x0002,
        uuid=UUID("ddddaaaa-aaaa-aa01-0000-000000000000"),
    ):
        """
        Contructor of a Provisionee (node) device
        Support for only one element per node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used for the node (elements and models layout), defaults to None
        :param prov_stack: Provisionning Stack to use, defaults to PBAdvBearerLayer
        :type prov_stack: Layer, optional
        :param net_key: If auto provisioned : primary NetKey , defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        :param dev_app_key: If auto provisioned : primary app key and dev key (both the same value), defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type dev_app_key: Bytes, optional
        :param unicast_addr: If auto provisioned, unicast addr, defaults to 0x0002
        :type unicast_addr: int, optional
        :param uuid: The UUID of the node, defaults to UUID("7462d668-bc88-3473-0000-000000000012")
        :type: UUID, optional
        """
        super().__init__(
            device,
            profile,
        )

        # Used to stop the unprov_beacons_sending_thread function from running
        self._unprov_beacons_sending = False

        # UUID of the node, used in beacons
        self.uuid = uuid

        self._prov_stack = prov_stack(connector=self, options={}, is_provisioner=False)

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU

        :param packet: Packet received
        :type packet: Packet
        """
        if not self.profile.is_provisioned:
            if packet.haslayer(EIR_PB_ADV_PDU):
                self._prov_stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            if (
                self.whitelist == []
                or packet.getlayer(BTLE_ADV_NONCONN_IND).AdvA in self.whitelist
            ):
                self._main_stack.on_net_pdu_received(
                    packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
                )

    def set_uuid(self, uuid):
        """
        Sets the UUID of the device for provisioning process
        IN THEORY SHOULD BE LINKED TO ADVA ADDRESS USED IN ADV PACKETS !

        :param uuid: UUID to use (16 bytes long hex string)
        :type uuid: str
        :returns: True if success, False if fail
        :rtype: bool
        """
        try:
            self.uuid = UUID(uuid)
        except Exception:
            return False

        return True

    def start_provisioning(self):
        """
        Starts the provisioning process (sending beacons, accepting invite ..) andf starts the connector for lisiting packets
        """
        self.start()
        self.start_unprovisioned_beacons_sending()

        self.prov_event = Event()

        auth_done = False

        while not self.profile.is_provisioned:
            # Check if event timedout, we fail
            if not self.prov_event.wait(timeout=10):
                self.stop_unprovisioned_beacons()
                return False

            elif not auth_done and self.prov_auth_data is not None:
                auth_done = True
                if self.prov_auth_data.auth_method == OUTPUT_OOB_AUTH:
                    print("AUTH VALUE IS : ")
                    print(self.prov_auth_data.value)

                # Input auth should be handled by user code or shell
                elif self.prov_auth_data.auth_method == INPUT_OOB_AUTH:
                    return self.prov_auth_data

        return True

    def start_unprovisioned_beacons_sending(self):
        """
        Starts the sending of an Unprovisioned Device Beacons (provisioning)
        """

        self._unprov_beacons_sending = True
        thread = Thread(target=self._unprov_beacons_sending_thread)
        thread.start()

    def stop_unprovisioned_beacons(self):
        """
        Stops the sending of BTMesh_Unprovisioned_Device_Beacon
        """
        self._unprov_beacons_sending = False

    def _unprov_beacons_sending_thread(self):
        """
        Thread that runs when sending unprovisioned device beacons
        """
        beacon_data = BTMesh_Unprovisioned_Device_Beacon(
            device_uuid=self.uuid, uri_hash=0
        )

        pkt_beacon = EIR_Hdr(type=0x2B) / EIR_BTMesh_Beacon(
            mesh_beacon_type=0x00, unprovisioned_device_beacon_data=beacon_data
        )
        for i in range(20):
            if not self._unprov_beacons_sending:
                return
            self.send_raw(pkt_beacon)
            sleep(2)

    def resume_provisioning_with_auth(self, value):
        """
        Resume the provisioning process with the user.

        :param value: The value types by the user
        :type value: str
        """

        self.prov_auth_data.value = value
        self._prov_stack.get_layer("pb_adv").on_provisioning_auth_data(
            self.prov_auth_data
        )
        self.prov_event = Event()
        self.prov_event.wait(20)
        return self.profile.is_provisioned

    def provisioning_complete(self, prov_data):
        """
        When Provisionning (not auto) is complete, we received the information to setup the node from the Provisioner and start normal behavior with main stack

        :param prov_data: The provisioning data content
        :type prov_data: ProvisioningCompleteData
        """

        primary_net_key = NetworkLayerCryptoManager(
            key_index=prov_data.key_index, net_key=prov_data.net_key
        )
        dev_key = UpperTransportLayerDevKeyCryptoManager(
            provisioning_crypto_manager=prov_data.provisioning_crypto_manager
        )
        self.profile.provision(
            primary_net_key,
            dev_key,
            prov_data.iv_index,
            prov_data.flags,
            prov_data.unicast_addr,
        )

        self._main_stack = NetworkLayer(connector=self, options=self.options)

        if self.prov_event is not None:
            self.prov_auth_data = None
            self.prov_event.set()

        """
    def handle_key_press(self, onoff, transaction_id):
        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=onoff, transaction_id=transaction_id)

        ctx = MeshMessageContext()
        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xff"
        ctx.ttl = 7
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = 0
        ctx.aid = (
            self.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
            .aid
        )
        pkt = BTMesh_Model_Message() / pkt
        self._main_stack.get_layer("access").process_new_message((pkt, ctx))

"""
