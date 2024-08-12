"""
Bluetooth Mesh Base connector.
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""

from random import randbytes
from whad.ble.connector import Sniffer
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.ble import UnsupportedCapability, message_filter, BleDirection
from queue import Queue, Empty
import pdb

from whad.bt_mesh.stack import PBAdvBearerLayer


class BTMesh(Sniffer):
    def __init__(self, device, stack=PBAdvBearerLayer, options={}):
        """
        Creates a Mesh generic Node

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :param stack: Stack to use, defaults to PBAdvBearerLayer
        :type stack: Stack, optional
        :param options: options de pass to stack, defaults to {}
        :type options: dict, optional
        :raises UnsupportedCapability: Device Cannot sniff or inject
        """
        """Create a Mesh generic Node"""
        super().__init__(device)
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self._stack = stack(connector=self, options=options)
        self.attach_callback(
            callback=lambda pkt: self.on_recv_adv(pkt),
            filter=lambda pkt: self.bt_mesh_filter(pkt, True),
            on_transmission=False,
        )

        # Queue of received messages, filled in on reception callback
        self.__queue = Queue()

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

    def on_recv_adv(self, packet):
        """
        Process an received advertising Mesh packet.
        Adds it to queue
        """
        #packet.show()
        self.__queue.put_nowait(packet)

    def polling_rx_packets(self):
        try:
            self.process_rx_packets(self.__queue.get_nowait())
        except Empty:
            pass

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Logic in subclasses

        :param packet: Packet received
        :type packet: Packet
        """
        #packet.show()
        pass

    def send_raw(self, packet, channel=37):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (EIR_Element subclass)
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """

        AdvA = randbytes(6).hex(":")  # random in spec
        adv_pkt = BTLE_ADV(TxAdd=1) / BTLE_ADV_NONCONN_IND(AdvA=AdvA, data=packet)

        return self.send_pdu(
            adv_pkt,
            access_address=0x8E89BED6,
            conn_handle=channel,
            direction=BleDirection.UNKNOWN,
        )
