"""
This module provides the :class:`whad.zigbee.connector.coordinator.Coordinator`
connector that allows creating a ZigBee coordinator tied to a WHAD device.

This coordinator creates its own network and accept end devices to join it. It
manages the join process and share the required encryption keys.
"""
from typing import List
from scapy.packet import Packet
from whad.zigbee.connector import Zigbee
from whad.dot15d4.stack import Dot15d4Stack
from whad.dot15d4.stack.mac import MACManager
from whad.zigbee.stack.nwk import NWKManager
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.nwk.network import ZigbeeNetwork
from whad.exceptions import UnsupportedCapability
from whad.device import WhadDevice

class Coordinator(Zigbee):
    """
    Zigbee Coordinator interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice, applications: List[ApplicationObject] = None):
        """ZigBee coordinator initialization.

        :param device: WHAD device to use as coordinator
        :type device: :class:`whad.device.WhadDevice`
        :param applications: list of application objects to add to the coordinator
        :type applications: list
        """
        super().__init__(device)

        if not self.can_be_coordinator():
            raise UnsupportedCapability("Coordinator")

        # Stack initialization
        MACManager.add(NWKManager)
        self.__stack = Dot15d4Stack(self)

        # Channel initialization
        self.__channel = 11
        self.__channel_page = 0

        self.enable_reception()

        self.__stack.get_layer('apl').get_application_by_name("zdo").configuration.get("configNodeDescriptor").logical_type = LogicalDeviceType.COORDINATOR
        self.__stack.get_layer('apl').initialize()
        self._init_applications(applications)

    def _init_applications(self, applications: List[ApplicationObject]):
        """Initialize the coordinator applications.

        :param applications: list of application objects to attach to the coordinator
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

    def start_network(self, channel: int = 23, ext_pan_id: int = 0x6055f90000f714e4,
                      network_key: bytes = None) -> ZigbeeNetwork:
        """Start ZigBee network: initialize the extended PAN ID for APS, set channel and
        define a default network key.

        :param channel: channel to use for this network (default: 23)
        :type channel: int, optional
        :param ext_pan_id: extended PAN ID (64 bits) value to use for this network
        :type ext_pan_id: int, optional
        :param network_key: network encryption key to use for this network
        :type network_key: bytes, optional
        :return: ZigBee network object on success, ``None`` on failure
        """
        self.__stack.get_layer('aps').database.set("apsUseExtendedPANID", ext_pan_id)
        self.__stack.get_layer('aps').database.set("apsUseChannel", channel)
        zdo = self.__stack.get_layer('apl').get_application_by_name('zdo')

        # Use a default network key if not specified
        if network_key is None:
            network_key = bytes.fromhex("ae197aa680491b06458ba5e3b4e040fe")
        zdo.security_manager.provision_network_key(network_key)

        # Start network manager
        if zdo.network_manager.startup():
            # Succeeded, return network object
            return zdo.network_manager.network
        else:
            # Failed
            return None

    def network_formation(self, pan_id: int = None, channel: int = None):
        """Form ZigBee network

        :param pan_id: short PAN ID (16 bits)
        :type pan_id: int, optional
        :param channel: channel number used by the network
        :type channel: int, optional
        :return: ZigBee network information
        """
        return self.__stack.get_layer('nwk').get_service("management").network_formation(
            pan_id = pan_id,
            channel = channel
        )

    @property
    def stack(self) -> Dot15d4Stack:
        """Current ZigBee stack
        """
        return self.__stack

    def enable_reception(self):
        """Enable coordinator mode on current channel.
        """
        self.set_coordinator_mode(channel=self.__channel)

    def set_channel(self, channel: int = 11):
        """Set current channel to ``channel``.

        :param channel: new channel number to use
        :type channel: int
        """
        self.__channel = channel
        self.enable_reception()

    def perform_ed_scan(self, channel: int = 11):
        """Perform an energy detection scan on channel.

        :param channel: channel on which energy detection scan has to be performed
        :type channel: int
        """
        if not self.can_perform_ed_scan():
            raise UnsupportedCapability("EnergyDetection")
        self.__channel = channel
        super().perform_ed_scan(channel)

    def set_channel_page(self, page: int = 0):
        """Set channel page.

        :param page: channel page to use
        :type page: int
        """
        if page != 0:
            raise UnsupportedCapability("ChannelPageSelection")
        else:
            self.__channel_page = page

    def get_channel(self) -> int:
        """Retrieve current channel number.

        :return: current channel number
        :rtype: int
        """
        return self.__channel

    def get_channel_page(self) -> int:
        """Retrieve the current channel page value

        :return: current channel page value
        :rtype: int
        """
        return self.__channel_page


    def send(self, pdu: Packet, channel: int = 11) -> bool:
        """Send pdu to network.

        :param pdu: pdu to send
        :type pdu: :class:`scapy.packet.Packet`
        :return: ``True`` on success, ``False`` otherwise
        :rtype: bool
        """
        return super().send(pdu, channel=self.__channel)

    def on_pdu(self, packet):
        """PDU handler.
        """
        if (
            hasattr(packet,"metadata") and
            hasattr(packet.metadata, "is_fcs_valid") and
            not packet.metadata.is_fcs_valid
        ):
            return

        self.__stack.on_pdu(packet)

    def on_ed_sample(self, timestamp: int, sample: int):
        """Process energy detection sample.

        :param timestamp: timestamp at which the energy detection sample has been measured
        :type timestamp: int
        :param sample: energy detection sample
        :type sample: int
        """
        self.__stack.on_ed_sample(timestamp, sample)
