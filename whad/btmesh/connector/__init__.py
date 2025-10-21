"""
Bluetooth Mesh Base connector.
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""

from scapy.layers.bluetooth4LE import (
    BTLE_ADV,
    EIR_Hdr,
)
from whad.ble.connector.base import BLE
from whad.exceptions import UnsupportedCapability
from whad.exceptions import WhadDeviceDisconnected

from scapy.layers.bluetooth4LE import BTLE_ADV, BTLE_ADV_NONCONN_IND
from whad.hub.ble import Direction as BleDirection


class Bearer:
    def __init__(self, connector):
        self.connector = connector
        self.configuration = {}

    def configure(self, **kwargs):
        for name, value in kwargs.items():
            print(name, "=>", value)
            self.configuration[name] = value

    def start(self):
        pass

    def stop(self):
        pass

    def send(self, pdu):
        pass


class AdvBearer(Bearer):
    
    def __init__(self, connector):
        super().__init__(connector)
        self.__started = False

        self.configuration = {
            "bd_address" : "AA:BB:CC:DD:EE:FF", 
            "channel" : None,
            "interval" : 50,
            "repeat" : 2
        }


    def configure(self, **kwargs):
        super().configure(**kwargs)
        if "bd_address" in kwargs:
            self.connector.set_bd_address(kwargs["bd_address"], public=False)

    def send(self, packet):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (EIR_Element subclass)
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """

        # If channel is None, transmit on every channel 37,38 & 39
        channel = self.configuration["channel"]
        if channel is None:
            channel = 0

        adv_pdu = BTLE_ADV_NONCONN_IND(
                AdvA=self.configuration["bd_address"],
                data=packet
        )

        for _ in range(self.configuration["repeat"]):
            res = self.connector.send_adv_pdu(
                    adv_pdu,
                    channel = channel
            )
        
        return res


    def start(self):
        """
        Start the adv bearer. 
        """

        if not self.connector.can_scan():
            raise UnsupportedCapability("Scan")

        scan_mode = self.connector.enable_scan_mode(
            interval=self.configuration["interval"]
        )
        if not scan_mode:
            return False

        if super(BTMesh, self.connector).start():
            self.__started = True

            return True
        return False

    def stop(self):
        """
        Stop the ADV bearer.
        """
        if self.__started:
            super(BTMesh, self.connector).stop()
            self.__started = False

    def on_adv_pdu(self, packet):
        """
        Callback called when an incoming advertising packet is received, 
        filters BT Mesh packets according to the ADV bearer.
        """  
        if self.bt_mesh_filter(packet):
            self.connector.process_rx_packets(packet)

    def bt_mesh_filter(self, packet, ignore_regular_adv=True):
        """
        Filter out non Mesh advertising packets
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any(
                        [
                            isinstance(i, EIR_Hdr) and i.type in (0x29, 0x2A, 0x2B)
                            for i in packet.data
                        ]
                    )
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

        return False

class BTMesh(BLE):
    """
    Connector class for Bluetooth Mesh device.
    Should not be used as is, inherited by Provisionee or Provisonner connectors (otherwise not provisioned and no stack instanced !!)

    Allows user code or shell to interact with the network, and also manages callbacks on received messages.
    """

    domain = "btmesh"

    def __init__(
        self,
        device,
    ):
        """
        Creates a BTMesh base connector

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :raises UnsupportedCapability: Device Cannot sniff
        """
        super().__init__(device)
        
        self.set_bearer(AdvBearer)
        self.bearer.configure(bd_address="AA:BB:CC:DD:EE:FF")

    def set_bearer(self, bearer):
        self.bearer = bearer(self)

    def on_adv_pdu(self, packet):
        """
        Process a received advertising Mesh packet.
        Adds it to queue
        """
        if self.bearer is not None:
            self.bearer.on_adv_pdu(packet)

    def send(self, packet):
        if self.bearer is not None:
            return self.bearer.send(packet)

        return False

    def start(self):
        if self.bearer is not None:
            return self.bearer.start()
        return False

    def stop(self):
        if self.bearer is not None:
            return self.bearer.stop()
        return False
    
    '''

    def send_raw(self, packet, channel=None, repeat=2):
        return self.send_adv_bearer(packet, channel=channel, repeat=repeat)

    def send_adv_bearer(self, packet, channel=None, repeat=2):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (EIR_Element subclass)
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """

        # If channel is None, transmit on every channel 37,38 & 39
        if channel is None:
            channel = 0

        adv_pdu = BTLE_ADV_NONCONN_IND(
                AdvA=self.mesh_bd_address,
                data=packet
        )
        for _ in range(repeat):
            res = self.send_adv_pdu(
                    adv_pdu,
                    channel = channel
            )
        
        return res
        '''
