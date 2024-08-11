"""
BLE Scanning device database
============================

This module provides a database that keeps track of discovered devices,
:class:`whad.ble.scanning.AdvertisingDevicesDB`. Discovered devices information
are handled in :class:`whad.ble.scanning.AdvertisingDevice`.
"""

from whad.esb.stack.llm.constants import ESBRole
from whad.esb.esbaddr import ESBAddress
from typing import List
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response

class CommunicatingDevice(object):
    """Store information about a device:

    * Received Signal Strength Indicator (RSSI)
    * Role (ptx or prx)
    * Applicative layer (if identified)
    * Set of used channels
    """

    def __init__(self, rssi, address, role, applicative_layer=None, channel=None):
        """Instantiate a CommunicatingDevice.

        :param  rssi:                   Received Signal Strength Indicator
        :type   rssi:                   float
        :param  address:                Device address
        :type   address:                str
        :param  role:                   Device role
        :type   role:                   :class:`whad.esb.ESBRole`
        :param  applicative_layer:       Scan response data
        :type   applicative_layer:      str
        :param  channel:               Last used channel
        :type   channel:               int
        """
        self.__address = ESBAddress(address)
        self.__role = role
        self.__applicative_layer = applicative_layer
        self.__rssi = rssi
        self.__channels = [channel]

    @property
    def address(self) -> str:
        """Device address.
        """
        return str(self.__address)

    @property
    def rssi(self) -> float:
        """Device RSSI.
        """
        return self.__rssi

    @property
    def role(self) -> ESBRole:
        """Device Role (Primary Transmitter (PTX) or Primary Receiver (PRX)).
        """
        return self.__role

    @property
    def channels(self) -> List[int]:
        """Channels used by the device.
        """
        return list(set(self.__channels))

    @property
    def last_channel(self) -> int:
        """Last channel used by the device.
        """
        if len(self.__channels) == 0:
            return None
        return self.__channels[-1]

    def __repr__(self):
        """Show device information.
        """
        # Do we have an applicative protocol identified ?
        if self.__applicative_layer is None:
            applicative_layer = ""
        else:
            applicative_layer = "(%s)"  % (self.__applicative_layer)

        # Display device role
        if self.__role == ESBRole.PRX:
            role = '[PRX]'
        else:
            role = '[PTX]'

        # Display channels list
        channels = (
            "channels=[%s] / last_channel=%4d" % (
                ", ".join([str(i) for i in self.channels]),
                self.last_channel
            )
        )
        if self.__rssi is not None:
            return '[%4d dBm] %s %s %s %s' % (
                self.__rssi,
                role,
                self.__address,
                channels,
                applicative_layer
            )
        else:
           return '%s %s %s %s' % (
                role,
                self.__address,
                channels,
                applicative_layer
            )

    def update_rssi(self, rssi=0):
        """Update device RSSI.

        :param  rssi: New RSSI value.
        :type   rssi: float
        """
        self.__rssi = rssi


    def update_channel(self, channel):
        """Update device channels in use.

        :param  channel: New RSSI value.
        :type   channel: float
        """
        self.__channels.append(channel)

    def set_applicative_layer(self, applicative_layer):
        """Update applicative layer.

        :param  applicative_layer: New applicative layer
        :type   applicative_layer:   str
        """
        if not self.__applicative_layer:
            self.__applicative_layer = applicative_layer


class CommunicatingDevicesDB(object):
    """Enhanced ShockBurst devices database.

    This class stores information about discovered devices.
    """

    def __init__(self):
        self.reset()


    def reset(self):
        """Remove database content.
        """
        self.__db = {}


    def find_device(self, address, role) -> CommunicatingDevice:
        """Find a device based on its address and role.

        :param      address: Enhanced ShockBurst address
        :type       address: str
        :param      role: Enhanced ShockBurst role
        :type       role: ESBRole
        :return:    Device if found, `None` otherwise.
        :rtype:     :class:`whad.esb.scanning.CommunicatingDevice`
        """
        if (address,role) in self.__db:
            return self.__db[(address,role)]
        else:
            return None


    def register_device(self, device):
        """Register or update a device.

        :param  device: Device to register.
        :type   device: :class:`whad.esb.scanning.CommunicatingDevice`
        """
        self.__db[(device.address,device.role)] = device


    def on_device_found(self, rssi, packet, filter_addr):
        """Device packet received.

        Parse the incoming packet and handle device appropriately.

        :param  rssi:           Received Signal Strength Indicator
        :type   rssi:           float
        :param  packet:         Received packet
        :type   packet:         :class:`scapy.packet.Packet`
        :param  filter_addr:    ESB address to filter
        :type   filter_addr:    str
        """
        address = ESBAddress(packet.metadata.address)
        if ESB_Payload_Hdr in packet:
            pdu = packet[ESB_Payload_Hdr:]
        else:
            pdu = ESB_Payload_Hdr()

        channel = packet.metadata.channel
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            role = ESBRole.PRX
        else:
            role = ESBRole.PTX

        applicative_layer = None

        payload = bytes(pdu)
        # Check if the payload is unifying
        if len(payload) >= 2 and payload[1] in (0x51,0xC2,0x40,0x4F,0xD3,0xC1,0xC3,0x5F,0x1F,0x0F,0x0E,0x10):
            checksum = 0x00
            for i in payload[:-1]:
                checksum = (checksum  - i) & 0xFF
            if checksum == payload[-1]:
                applicative_layer = "unifying"

        # If bd address does not match, don't report it
        if filter_addr is not None and filter_addr.lower() != str(address).lower():
            return

        existing_device = self.find_device(str(address),role)
        if existing_device is None:
            new_device = CommunicatingDevice(
                rssi,
                str(address),
                role,
                applicative_layer,
                channel
            )
            self.register_device(new_device)
            return new_device
        else:
            existing_device.update_rssi(rssi)
            existing_device.update_channel(channel)
            if applicative_layer is not None:
                existing_device.set_applicative_layer(applicative_layer)
