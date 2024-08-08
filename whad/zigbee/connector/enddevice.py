"""
This module provides the :class:`whad.zigbee.connector.enddevice.EndDevice`
connector that allows the creation of a ZigBee end device.

This connector is able to discover networks and based on a discovered network
to join it (if permitted) and act as an End Device in this network.
"""
from typing import List, Union
from scapy.packet import Packet
from whad.zigbee.connector import Zigbee
from whad.dot15d4.stack import Dot15d4Stack
from whad.dot15d4.stack.mac import MACManager
from whad.zigbee.stack.nwk import NWKManager
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.nwk.network import ZigbeeNetwork
from whad.exceptions import UnsupportedCapability
from whad.device import WhadDevice

class EndDevice(Zigbee):
    """
    Zigbee End Device interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice, applications: List[ApplicationObject] = None):
        """ZigBee End Device connector initialization.

        :param device: WHAD device
        :type device: :class:`whad.device.WhadDevice`
        :param applications: list of application objects to use with this end device
        :type applications: list
        """
        super().__init__(device)

        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        # Stack initialization
        MACManager.add(NWKManager)
        self.__stack = Dot15d4Stack(self)

        # Channel initialization
        self.__channel = 11
        self.__channel_page = 0

        self.enable_reception()
        zdo = self.__stack.get_layer('apl').get_application_by_name("zdo")
        zdo.configuration.get("configNodeDescriptor").logical_type = LogicalDeviceType.END_DEVICE
        self.__stack.get_layer('apl').initialize()
        self._init_applications(applications)

    def _init_applications(self, applications: List[ApplicationObject]):
        """Initialize ZigBee application objects attached to the end device.
        If no application is defined, add a default ZigBee Cluster Library application
        object.

        :param applications: list of application objects to attach to the end device
        :type applications: list
        """
        if applications is None:
            # If no application provided, attach a default ZCL application on endpoint 1
            app = ApplicationObject("zcl_app", 0x0104, 0x0100, device_version=0,
                                    input_clusters=[], output_clusters=[])
            self.__stack.get_layer('apl').attach_application(app, endpoint=1)

        else:
            for app in applications:
                endpoint = 1
                self.__stack.get_layer('apl').attach_application(app, endpoint=endpoint)
                endpoint += 1

    def discover_networks(self) -> List[ZigbeeNetwork]:
        """Discover ZigBee networks.

        :return: list of discovered ZigBee networks
        :rtype: list
        """
        return self.__stack.get_layer('apl').get_application_by_name("zdo").network_manager.discover_networks()

    @property
    def stack(self):
        """Current ZigBee stack
        """
        return self.__stack

    def enable_reception(self):
        """Enable reception mode on the currently selected channel (enable
        device mode).
        """
        self.set_end_device_mode(channel=self.__channel)

    def set_channel(self, channel: int = 11):
        """Set ZigBee channel to use for the end device.

        :param channel: channel to use
        :type channel: int
        """
        self.__channel = channel
        self.enable_reception()

    def perform_ed_scan(self, channel: int = 11) -> bool:
        """Perform an energy detection scan on the specified channel.

        :param channel: channel on which the detection will be performed
        :type channel: int
        :return: ``True`` on success, ``False`` otherwise.
        :rtype: bool
        """
        if not self.can_perform_ed_scan():
            raise UnsupportedCapability("EnergyDetection")
        self.__channel = channel
        return super().perform_ed_scan(channel)

    def set_channel_page(self, page: int = 0):
        """Set ZigBee channel page for the end device

        :param page: channel page to use
        :type page: int
        """
        if page != 0:
            raise UnsupportedCapability("ChannelPageSelection")
        else:
            self.__channel_page = page

    def get_channel(self) -> int:
        """Retrieve the currently selected channel.

        :return: current ZigBee channel number
        :rtype: int
        """
        return self.__channel

    def get_channel_page(self) -> int:
        """Retrieve the current channel page

        :return: current channel page value
        :rtype: int
        """
        return self.__channel_page


    def send(self, pdu: Union[Packet, bytes], channel: int = None):
        """Send a PDU to the associated network, if any.

        :param pdu: pdu to send
        :type pdu: :class:`scapy.packet.Packet`
        :type pdu: bytes
        :param channel: channel on which to send the pdu
        :type channel: int, optional
        """
        # Forward to Dot15d4 (override channel parameter)
        super().send(pdu, channel=self.__channel)

    def on_pdu(self, packet: Packet):
        """ZigBee received PDU handler.

        :param packet: received packet (PDU)
        :type packet: :class:`scapy.packet.Packet`
        """
        if (
            hasattr(packet,"metadata") and
            hasattr(packet.metadata, "is_fcs_valid") and
            not packet.metadata.is_fcs_valid
        ):
            return

        self.__stack.on_pdu(packet)

    def on_ed_sample(self, timestamp: int, sample: int):
        """Process receive energy detection sample.

        :param timestamp: timestamp in microseconds
        :type timestamp: int
        :param sample: sample measured
        :type sample: int
        """
        self.__stack.on_ed_sample(timestamp, sample)