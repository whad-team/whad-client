from scapy.layers.zigbee import ZigBeeBeacon
from .exceptions import NWKTimeoutException
from .constants import ZigbeeNetwork
from whad.zigbee.stack.mac.constants import MACScanType
from queue import Queue, Empty
from time import time

class NWKService(object):
    """
    This class represents a NWK service, exposing a standardized API.
    """
    def __init__(self, manager):
        self._manager = manager
        self._queue = Queue()

    def wait_for_message(self, message_clazz, timeout=1.0):
        """Wait for a specific message type or error, other messages are dropped

        :param type message_clazz: Expected message class
        :param float timeout: Timeout value (default: 30 seconds)
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self._queue.get(block=False,timeout=0.5)
                if message_clazz in msg:
                    return msg
            except Empty:
                pass
        raise NWKTimeoutException

class NWKDataService(NWKService):
    """
    NWK service processing Data packets.
    """
    pass

class NWKManagementService(NWKService):
    """
    NWK service processing Management packets.
    """
    def ed_scan(self, scan_channels=0x7fff800, scan_duration=2):
        """
        Implements the NLME-ED-SCAN request.
        """
        confirm = self._manager.mac_management_service.scan(
            scan_type=MACScanType.ENERGY_DETECTION,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )
        return confirm

    def network_discovery(self, scan_channels=0x7fff800, scan_duration=2):
        """
        Implements the NLME-NETWORK-DISCOVERY request.
        """
        confirm = self._manager.mac_management_service.scan(
            scan_type=MACScanType.ACTIVE,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )
        zigbee_networks = []
        notifications_left = True
        while notifications_left:
            try:
                beacon = self.wait_for_message(ZigBeeBeacon)
                if beacon.pan_descriptor in confirm:
                    zigbee_networks.append(ZigbeeNetwork(beacon))
            except NWKTimeoutException:
                notifications_left = False
        return zigbee_networks

    def on_beacon_pdu(self, pan_descriptor, beacon_payload):
        beacon_payload.pan_descriptor = pan_descriptor
        self._queue.put(beacon_payload, block=True)

class NWKManager:
    """
    This class implements the Zigbee Network manager (NWK).
    It handles network-level operations, such as discovery, association or network initiation.

    It exposes two services providing the appropriate API.
    """
    def __init__(self, mac=None):
        self.__mac = mac
        self.__mac_management_service = self.__mac.management_service
        self.__mac_data_service = self.__mac.data_service

        self.__data_service = NWKDataService(self)
        self.__management_service = NWKManagementService(self)

    @property
    def services(self):
        return self.__management_service, self.__data_service

    @property
    def mac_management_service(self):
        return self.__mac_management_service

    @property
    def mac_data_service(self):
        return self.__mac_data_service

    def on_beacon_pdu(self, pan_descriptor, beacon_payload):
        if isinstance(beacon_payload, bytes):
            beacon_payload = ZigBeeBeacon(beacon_payload)
        # Check if this is a Zigbee beacon
        if hasattr(beacon_payload, "proto_id") and beacon_payload.proto_id == 0:
            self.__management_service.on_beacon_pdu(pan_descriptor, beacon_payload)
