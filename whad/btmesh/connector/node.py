"""
Bluetooth Mesh Base connector for nodes (Provisionee or Provisioner).
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""

from tarfile import TarError
from scapy.layers.bluetooth4LE import BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.scapy.layers.btmesh import (
    BTMesh_Unprovisioned_Device_Beacon,
    EIR_Hdr,
    EIR_PB_ADV_PDU,
    BTMesh_Obfuscated_Network_PDU,
    EIR_BTMesh_Beacon,
    BTMesh_Model_Message,
)
from whad.ble import Peripheral
from whad.hub.ble import Direction as BleDirection
from whad.exceptions import (
    UnsupportedCapability,
    WhadDeviceAccessDenied,
    WhadDeviceError,
)
from whad.exceptions import WhadDeviceDisconnected
from whad.btmesh.stack.exceptions import InvalidModelToSend
from queue import Queue, Empty
from time import sleep
from threading import Thread, Lock, Event
from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.stack.network import NetworkLayer
from whad.btmesh.connector import BTMesh
from whad.btmesh.models import ModelClient
from whad.btmesh.stack.utils import MeshMessageContext

from whad.btmesh.profile import BaseMeshProfile
from copy import copy


# lock for sending to not skip packets ?
def txlock(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result

    return _wrapper


class BTMeshNode(BTMesh):
    """
    Connector class for Bluetooth Mesh device (Rx and Tx capabilities needed)
    Should not be used as is, inherited by Provisionee or Provisonner connectors (otherwise not provisioned and no stack instanced !!)

    Allows user code or shell to interact with the network, and also manages callbacks on received messages.
    """

    def __init__(
        self,
        device,
        profile=None,
    ):
        """
        Creates a Mesh generic Node

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :param profile: The profile instance to use 
        :type profile: BaseMeshProfile, optional
        :type prov_stack: Layer, optional
        :raises UnsupportedCapability: Device Cannot inject
        """
        super().__init__(device)
        #if not self.can_inject():
        #    raise UnsupportedCapability("Inject")

        # Queue of received messages, filled in on reception callback
        self.__queue = Queue()

        self.__tx_lock = Lock()

        if profile is None:
            self.profile = BaseMeshProfile()
        else:
            self.profile = profile

        self.options = {
            "profile": self.profile,
            "lower_transport": {
                "profile": self.profile,
                "upper_transport": {
                    "profile": self.profile,
                    "access": {"profile": self.profile},
                },
            },
        }

        self.polling_rx_packets_thread = None

        self.is_listening = False

        self.whitelist = []

        self._main_stack = NetworkLayer(connector=self, options=self.options)

        # Provisionning stack, (probably reinstancd by Provisioner/Provisionee)
        self._prov_stack = PBAdvBearerLayer(connector=self, options={})
        # used to communicate with Shell/terminal to prompt user to type authentication value (provisioning)
        self.prov_event = None

        # Provisionning auth data received from the stack (Provisioner and provisionee)
        self.prov_auth_data = None

        # Data from the provisioning process (of local node if provisionee, distant node if Provisioner)
        self._prov_data = None

        # Channel we listen on (regularly changed by thread change_sniffing_channel)
        self.channel = 37

        self.sniffer_channel_switch_thread = None
        self.sniffing_event = None

    @property
    def main_stack(self):
        return self._main_stack

    @main_stack.setter
    def main_stack(self, value):
        self._main_stack = value

    @property
    def prov_stack(self):
        return self._prov_stack

    @prov_stack.setter
    def prov_stack(self, value):
        self._prov_stack = value

    def lock_tx(self):
        self.__tx_lock.acquire()

    def unlock_tx(self):
        self.__tx_lock.release()

    def on_adv_pdu(self, packet):
        """
        Process a received advertising Mesh packet.
        Adds it to queue
        """
        if not self.bt_mesh_filter(packet, True):
            return
        self.__queue.put(packet)

    def start(self):
        if not self.is_listening:
            super().start()
            self.is_listening = True
            if self.can_sniff_advertisements():
                self.sniff_advertisements(channel=self.channel)
            else:
                self.enable_scan_mode()
            if self.sniffing_event is not None:
                self.sniffing_event.set()
                self.sniffing_event = None

            self.sniffing_event = Event()
            self.polling_rx_packets_thread = Thread(
                target=self.polling_rx_packets, args=(self.sniffing_event,)
            )
            self.polling_rx_packets_thread.start()

            self.sniffer_channel_switch_thread = Thread(
                target=self.change_sniffing_channel, args=(self.sniffing_event,)
            )
            self.sniffer_channel_switch_thread.start()

    def stop(self):
        if self.is_listening:
            self.is_listening = False
            if self.sniffing_event is not None:
                self.sniffing_event.set()

            super().stop()

    def polling_rx_packets(self, sniffing_event):
        while not sniffing_event.is_set():
            try:
                self.process_rx_packets(self.__queue.get(timeout=0.01))
            except Empty:
                pass
            # Handle device disconnection
            except WhadDeviceDisconnected:
                return

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU OR
        initiates provisioning if unprovisioned beacon

        :param packet: Packet received
        :type packet: Packet
        """
        if packet.haslayer(EIR_BTMesh_Beacon):
            self.process_beacon(packet.getlayer(EIR_BTMesh_Beacon))
        elif packet.haslayer(EIR_PB_ADV_PDU):
            self._prov_stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif self.profile.is_provisioned and packet.haslayer(
            BTMesh_Obfuscated_Network_PDU
        ):
            self._main_stack.on_net_pdu_received(
                packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
            )

    def process_beacon(self, packet):
        """
        Process a received beacon, not supported yet
        unprovisioned_device_beacons handled in Provisioner

        :param packet:
        :type packet: EIR_BTMesh_Beacon
        """
        pass

    @txlock
    def send_raw(self, packet, channel=37):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (EIR_Element subclass)
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """
        # AdvA = randbytes(6).hex(":")  # random in spec
        AdvA = (self.profile.get_primary_element_addr() & 0xFF).to_bytes(
            1, "big"
        ) + b"\xaa\xaa\xaa\xaa\xaa"
        adv_pkt = BTLE_ADV(
            TxAdd=0, RxAdd=0, ChSel=0, RFU=0, PDU_type=2
        ) / BTLE_ADV_NONCONN_IND(AdvA=AdvA, data=packet)
        for i in range(0, 2):
            self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=39,
                direction=BleDirection.UNKNOWN,
            )
            sleep(0.005)
            self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=37,
                direction=BleDirection.UNKNOWN,
            )
            sleep(0.002)
            res = self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=38,
                direction=BleDirection.UNKNOWN,
            )
            sleep(0.007)
        return res

    def change_sniffing_channel(self, sniffing_event):
        channels = [37, 38, 39]
        i = 0
        while not sniffing_event.is_set():
            try:
                self.stop()
                self.channel = channels[i]
                self.start()
                i = (i + 1) % 3
                sleep(0.1)
            except:
                return

    def do_secure_network_beacon(self, key_refresh, iv_update):
        """
        Sends a secure network beacon to the network with the given arguments

        :param key_refresh: Key refresh flag
        :type key_refresh: int
        :param iv_update: IV update flag
        :type iv_update: int
        """

        if self.profile.is_provisioned:
            self._main_stack.get_layer("network").send_secure_network_beacon(
                key_refresh, iv_update
            )

    def reset_whitelist(self):
        """
        Resets the whitelist
        """
        self.whitelist = []

    def add_whitelist(self, addr):
        """
        Adds an address to the whitelist

        :param addr: BD Addr to add
        :type addr: str
        """
        addr = addr.lower()
        if addr not in self.whitelist:
            self.whitelist.append(addr)

    def remove_whitelist(self, addr):
        """
        Removes an address from the whitelist

        :param addr: BD Addr to remove
        :type addr: str
        """
        try:
            index = self.whitelist.index(addr.lower())
        except ValueError:
            return
        self.whitelist.pop(index)

    def send_raw_access(self, message):
        """
        Sends a message created from raw hex string and its context to the access layer to be sent to the network

        :param message: Message and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        if self.profile.is_provisioned:
            self._main_stack.get_layer("access").send_direct_message(message)

    def on_provisioning_complete(self, prov_data):
        """
        Notification from the provisioning layer that a distant node has been provisioned or that we are provisioned

        :param prov_data:Data sent to the distant node
        """
        self._prov_data = prov_data
        self.prov_event.set()

    def provisioning_auth_data(self, message):
        """
        Handler of a ProvisionningAuthenticationData received from the stack.

        :param message: The ProvisionningAuthenticationData receoved
        :type message: ProvisionningAuthenticationData
        """

        self.prov_auth_data = message
        if self.prov_event is not None:
            self.prov_event.set()

    def send_model_message(
        self, model, message, is_acked=False, expected_response_clazz=None, timeout=3
    ):
        """
        Sends a message from the model (client) specified.
        The message should be a valid message sent by the model specified (no BTMesh_Model_Message layer needed !)

        Handlers to send these messages are defined in the `handler` object of the ModelClient object.
        If is_acked is True, message is expecting a Status response before Timeout.

        Blocking function for timeout time maximum.

        :param model: The model to send the message from. If Acked message, will handle the response and return relevant information (based on handler implementation).
        :type model: ModelClient
        :param message: The Model message to send. Context can be None or non existant, use of default values.
        :type message: (BTMesh_Model_Message, MeshMessageContext | None)  | BTMesh_Model_Message
        :param is_acked: Is the message acked, defaults to False
        :type is_acked: bool, optional
        :param expected_response_clazz: Expected class of the response if acked. Should be a valid message listed in hanlders of model. If not specified, first valid message received in model processed, defaults to None
        :param expected_response_clazz: Any
        :param timeout: Timeout delay before if message is acked and no response received (in sec), defaults to 3
        :type timeout: int, optional
        :returns: If unacked message, None. If acked, returns the status packet (or custom return in Model has specific implementation) or None
        :rtype: Any
        :raises InvalidModelToSend: [TODO:description]
        """
        if not isinstance(model, ModelClient):
            raise InvalidModelToSend(
                "This model is not a ModelClient, cannot send messages from it."
            )
        if not self.profile.is_provisioned:
            return None

        try:
            pkt, ctx = message
            # Copy the context so that the user can resuse the same one without having some values overwritten by the stack...
            ctx = copy(ctx)
        except TypeError:
            pkt = message
            ctx = MeshMessageContext()
            ctx.src_addr = self.profile.get_primary_element_addr() + model.element_index
            ctx.dest_addr = 0xFFFF
            ctx.application_key_index = 0
            ctx.net_key_id = 0
            ctx.ttl = 127

        if not pkt.haslayer(BTMesh_Model_Message):
            pkt = BTMesh_Model_Message() / pkt

        return self._main_stack.get_layer("access").send_access_message(
            model,
            (pkt, ctx),
            is_acked,
            expected_response_clazz,
            timeout,
        )

    def do_network_discovery(self, addr_low, addr_high, delay=3.5):
        """
        launch the network discovery "attack" via Directed Forwarding

        :param addr_low: Lowest address to test
        :type addr_low: int
        :param addr_high: Highest address to test
        :type addr_high: int
        :param delay: Delay between 2 Path Requests, defaults to 3.5
        :type delay: float, optional
        """
        if self.profile.is_provisioned:
            thread = Thread(
                target=self._main_stack.get_layer(
                    "upper_transport"
                ).discover_topology_thread,
                args=[addr_low, addr_high, delay],
            )
            thread.start()

    def do_get_hops(self):
        """
        Get the distance between attacker to discovred nodes via network discovery attack
        """
        if self.profile.is_provisioned:
            thread = Thread(
                target=self._main_stack.get_layer(
                    "upper_transport"
                ).discovery_get_hops_thread
            )
            thread.start()
