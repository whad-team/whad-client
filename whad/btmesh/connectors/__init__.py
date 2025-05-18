"""
Bluetooth Mesh Base connector.
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""

from whad.ble.connector import Sniffer
from scapy.layers.bluetooth4LE import BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.ble import UnsupportedCapability, BleDirection, Peripheral
from whad.exceptions import WhadDeviceDisconnected
from queue import Queue, Empty
from time import sleep
from threading import Thread, Lock
from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.stack.network import NetworkLayer

from whad.btmesh.profile import BaseMeshProfile


# lock for sending to not jam ?
def txlock(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result

    return _wrapper


class BTMesh(Sniffer):
    """
    Connector class for Bluetooth Mesh device.
    Should not be used as is, inherited by Provisionee or Provisonner connectors (otherwise not provisioned and no stack instanced !!)

    Allows user code or shell to interact with the network, and also manages callbacks on received messages.
    """

    def __init__(
        self,
        device,
        profile=BaseMeshProfile(),
        prov_stack=PBAdvBearerLayer,
        is_provisioner=False,
        options={},
    ):
        """
        Creates a Mesh generic Node

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :param prov_stack: Provisionning Stack to use, defaults to PBAdvBearerLayer
        :type prov_stack: Stack, optional
        :param is_provisioner: Is the node we create a provisiner node ? defaults to False
        :type is_provisioner: bool, optional
        :param options: options de pass to provisioning stack, defaults to {}
        :type options: dict, optional
        :raises UnsupportedCapability: Device Cannot sniff or inject
        """
        super().__init__(device)
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self._prov_stack = prov_stack(
            connector=self, options=options, is_provisioner=is_provisioner
        )

        # Queue of received messages, filled in on reception callback
        self.__queue = Queue()

        self.__tx_lock = Lock()

        # The stack used after provisioning (instanced after)
        self._main_stack = None

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

        self.sniffer_channel_switch_thread = Thread(
            target=self.change_sniffing_channel
        ).start()

        self.configure(advertisements=True, connection=False)

        self.polling_rx_packets_thread = None

        self.is_listening = True

        self.whitelist = []

        self._main_stack = NetworkLayer(connector=self, options=self.options)

        # used to communicate with Shell/terminal to prompt user to type authentication value (provisioning)
        self.prov_event = None

        # Provisionning auth data received from the stack (Provisioner and provisionee)
        self.prov_auth_data = None

    def lock_tx(self):
        self.__tx_lock.acquire()

    def unlock_tx(self):
        self.__tx_lock.release()

    def bt_mesh_filter(self, packet, ignore_regular_adv):
        """
        Filter out non Mesh advertising packets
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any([i.type in (0x29, 0x2A, 0x2B) for i in packet.data])
                    or any(
                        h in [[0x1827], [0x1828]]
                        for h in [
                            i.svc_uuids
                            for i in packet.data
                            if hasattr(i, "svc_uuids") and not ignore_regular_adv
                        ]
                    )
                ):
                    return True

    def on_adv_pdu(self, packet):
        """
        Process a received advertising Mesh packet.
        Adds it to queue
        """

        if not self.bt_mesh_filter(packet, True):
            return
        self.__queue.put(packet)

    def start(self):
        super().start()
        self.start_listening()

    def start_listening(self):
        self.is_listening = True
        self.polling_rx_packets_thread = Thread(target=self.polling_rx_packets)
        self.polling_rx_packets_thread.start()

    def stop_listening(self):
        self.is_listening = False

    def polling_rx_packets(self):
        while self.is_listening:
            try:
                self.process_rx_packets(self.__queue.get())
            except Empty:
                sleep(0.001)
            # Handle device disconnection
            except WhadDeviceDisconnected:
                return

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Logic in subclasses

        :param packet: Packet received
        :type packet: Packet
        """
        # packet.show()
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
        AdvA = (self.profile.primary_element_addr & 0xFF).to_bytes(
            1, "big"
        ) + b"\xaa\xaa\xaa\xaa\xaa"
        adv_pkt = BTLE_ADV(TxAdd=0) / BTLE_ADV_NONCONN_IND(AdvA=AdvA, data=packet)
        for i in range(0, 2):
            self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=39,
                direction=BleDirection.UNKNOWN,
            )
            self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=37,
                direction=BleDirection.UNKNOWN,
            )
            res = self.send_pdu(
                adv_pkt,
                access_address=0x8E89BED6,
                conn_handle=38,
                direction=BleDirection.UNKNOWN,
            )
            sleep(0.003)
        return res

    def change_sniffing_channel(self):
        channels = [37, 38, 39]
        i = 0
        while True:
            self.channel = channels[i]
            i = (i + 1) % 3
            sleep(0.03)

    def do_secure_network_beacon(self, key_refresh, iv_update):
        """
        Sends a secure network beacon to the network with the given arguments

        :param key_refresh: Key refresh flag
        :type key_refresh: int
        :param iv_update: IV update flag
        :type iv_update: int
        """

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

    def do_onoff(self, value, ctx, tid):
        """
        Sends a Generic On/Off set message (acked or unacked)

        :param value: Value to be set (0 or 1)
        :type value: int
        :param ctx: Context of the message
        :type ctx: MeshMessageContext
        :param tid: Transaction Id
        :type tid: int
        """
        self._main_stack.get_layer("access").do_onoff(value, ctx, tid)

    def set_relay(self, onoff):
        """
        Enables of disabled relaying on the NetworkLayer

        :param onoff: Set the relay on or off
        :type onoff: boolean
        """
        self._main_stack.get_layer("network").state.is_relay_enabled = onoff

    def get_relaying_status(self):
        """
        Returns whether the relaying is enabled or not
        """
        return self._main_stack.get_layer("network").state.is_relay_enabled

    def send_raw_access(self, message):
        """
        Sends a message created from raw hex string and its context to the access layer to be sent to the network

        :param message: Messsage and its context
        :type message: (BTMesh_Model_Messsage, MeshMessageContext)
        """
        self._main_stack.get_layer("access").process_new_message(message)

    def set_capability(self, name, value):
        """
        On the Provisionning layer, set the value of the specified capability
        Returns True if success, False if fail

        :param name: Name of the capability
        :type name: str
        :param value: Value to set
        :type value: int
        """
        return self._prov_stack.get_layer("pb_adv").set_capability(name, value)

    def get_capabilities(self):
        """
        On the Provisionning layer, returns the dict of capabilities of the node

        :returns: The dict of capabilities of the node
        :rtype: dict
        """
        return self._prov_stack.get_layer("pb_adv").get_capabilities()

    def provisonning_auth_data(self, message):
        """
        Handler of a ProvisionningAuthenticationData received from the stack.

        :param message: The ProvisionningAuthenticationData receoved
        :type message: ProvisionningAuthenticationData
        """

        self.prov_auth_data = message
        if self.prov_event is not None:
            self.prov_event.set()


class BTMeshHCI(Peripheral):
    """
    Creates a Mesh generic Node, only using HCI commands

    :param device: Whad device handle
    :type device: WhadDeviceConnector
    :param stack: Stack to use, defaults to PBAdvBearerLayer
    :type stack: Stack, optional
    :param options: options de pass to stack, defaults to {}
    :type options: dict, optional
    :raises UnsupportedCapability: Device Cannot sniff or inject
    """

    def __init__(self, device, stack=PBAdvBearerLayer, options={}):
        super().__init__(device)
