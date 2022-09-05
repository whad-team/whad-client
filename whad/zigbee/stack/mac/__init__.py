from .constants import MACScanType, MACConstants, MACAddressMode, Dot15d4PANNetwork, \
    EDMeasurement, MACDeviceType, MACPowerSource
from whad.zigbee.stack.constants import SYMBOL_DURATION
from .exceptions import MACTimeoutException
from whad.exceptions import RequiredImplementation
from queue import Queue, Empty
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Beacon, Dot15d4Cmd, \
    Dot15d4Ack, Dot15d4, Dot15d4CmdAssocReq
from scapy.config import conf
from time import time,sleep
from whad.zigbee.stack.nwk import NWKManager

class MACPIB:
    """
    802.15.4 MAC PIB Database of attributes.
    """
    def __init__(self):
        self.reset()

    def reset(self):
        """
        Reset the PIB database to its default value.
        """
        self.macExtendedAddress = None
        self.macAssociatedPanCoord = False
        self.macAssociationPermit = False
        self.macAutoRequest = True
        self.macDataSequenceNumber = 0
        self.macBeaconSequenceNumber = 0
        self.macPanId = 0
        self.macCoordShortAddress = 0
        self.macCoordExtendedAddress = 0

    def get(self, attribute):
        """
        Read a given database attribute.
        """
        if hasattr(self, attribute):
            return getattr(self, attribute)
        return None

    def set(self, attribute, value):
        """
        Write a value to a given database attribute.
        """
        if hasattr(self, attribute):
            setattr(self, attribute, value)
            return True
        return False


class MACService(object):
    """
    This class represents a MAC service, exposing a standardized API.
    """
    def __init__(self, manager):
        self._manager = manager
        self._queue = Queue()

    def wait_for_message(self, message_clazz, timeout=5.0):
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
        raise MACTimeoutException

class MACDataService(MACService):
    """
    MAC service processing Data packets.
    """
    def on_data_pdu(self, pdu):
        pass

    def on_ack_pdu(self, pdu):
        pass

class MACManagementService(MACService):
    """
    MAC service processing Management packets.
    """
    def __init__(self, manager):
        super().__init__(manager)
        self._samples_queue = Queue()

    def get(self, attribute):
        """
        Implement the MLME-GET request operation.
        """
        return self._manager.pib.get(attribute)

    def set(self, attribute, value):
        """
        Implement the MLME-SET request operation.
        """
        return self._manager.pib.set(attribute, value)

    def reset(self, set_default_pib=True):
        """
        Implement the MLME-RESET request operation.
        """
        if set_default_pib:
            self._manager.pib.reset()

    def associate(self, channel_page=0, channel=11, coordinator_address_mode=MACAddressMode.SHORT, coordinator_pan_id=0, coordinator_address=0, device_type=MACDeviceType.FFD, power_source=MACPowerSource.ALTERNATING_CURRENT_SOURCE, idle_receiving=True, allocate_address=True, security_capability=True, fast_association=False):
        """
        Implement the MLME-ASSOCIATE request operation.
        """
        self._manager.set_channel_page(channel_page)
        self._manager.set_channel(channel)
        print("Channel", channel)

        acked = self._manager.send_data(
                Dot15d4Cmd(
                    cmd_id="AssocReq",
                    dest_addr=coordinator_address,
                    dest_panid=coordinator_pan_id
                )/
                Dot15d4CmdAssocReq(
    				allocate_address=int(allocate_address),
    				security_capability = int(security_capability),
    				power_source=int(power_source == MACPowerSource.ALTERNATING_CURRENT_SOURCE),
    				device_type=int(device_type == MACDeviceType.FFD),
    				receiver_on_when_idle=int(idle_receiving),
    				alternate_pan_coordinator=int(fast_association)
    		  )
            , wait_for_ack=True)

        if acked:
            self._manager.send_data(
                Dot15d4Cmd(
                    cmd_id="DataReq",
                    dest_addr=coordinator_address,
                    dest_panid=coordinator_pan_id
                ),
                wait_for_ack=True
            )

    def scan(self, scan_type=MACScanType.ACTIVE,channel_page=0, scan_channels=0x7fff800, scan_duration=5):
        """
        Implement the MLME-SCAN request operation.
        """
        # Convert channel map to channels list
        if isinstance(scan_channels, int):
            channels = []
            for i in range(0,27):
                if scan_channels & (1 << i) != 0:
                    channels.append(i)
        elif isinstance(scan_channels, list):
            channels = scan_channels
        else:
            return False

        # Check scan_duration validity
        if scan_duration < 0 or scan_duration > 14:
            return False

        # Convert scan duration
        duration = MACConstants.A_BASE_SUPERFRAME_DURATION * ((2**scan_duration) + 1) * SYMBOL_DURATION[self._manager.stack.phy]

        # Select the right scan
        if scan_type == MACScanType.ACTIVE:
            return self._perform_legacy_scan(channel_page, channels, duration, active=True)
        elif scan_type == MACScanType.PASSIVE:
            return self._perform_legacy_scan(channel_page, channels, duration, active=False)
        elif scan_type == MACScanType.ENERGY_DETECTION:
            return self._perform_ed_scan(channel_page, channels, duration)
        else:
            raise RequiredImplementation("Scan")

    # Helpers
    def _perform_legacy_scan(self, channel_page, channels, duration, active=True):
        pan_descriptors = []
        for channel in channels:
            self._manager.set_channel_page(channel_page)
            self._manager.set_channel(channel)
            print("Channel", channel)
            start_time = time()* 1000000
            if active:
                self._manager.send_data(Dot15d4Cmd(
                    cmd_id="BeaconReq",
                    dest_addr=0xFFFF,
                    dest_panid=0xFFFF)
                )

            while (time()* 1000000 - start_time) < duration:
                try:
                    beacon = self.wait_for_message(Dot15d4Beacon, timeout=0.0001)
                    pan_descriptor = Dot15d4PANNetwork(beacon, channel_page, channel)
                    self._manager.notify_beacon(pan_descriptor, beacon[Dot15d4Beacon].payload)
                    if pan_descriptor not in pan_descriptors:
                        pan_descriptors.append(pan_descriptor)
                except MACTimeoutException:
                    pass
        return pan_descriptors


    def _perform_ed_scan(self, channel_page, channels, duration):
        ed_measurements = []
        for channel in channels:
            self._manager.set_channel_page(channel_page)
            self._samples_queue.queue.clear()
            self._manager.perform_ed_scan(channel)

            start_time = time()* 1000000
            samples = []
            while (time()* 1000000 - start_time) < duration:
                try:
                    sample = self._samples_queue.get(block=False)
                    samples.append(sample)
                except Empty:
                    pass
            ed_measurements.append(EDMeasurement(samples, channel_page, channel))
        return ed_measurements

    # Event processing
    def on_cmd_pdu(self, pdu):
        pdu.show()

    def on_beacon_pdu(self, pdu):
        self._queue.put(pdu, block=True, timeout=None)

    def on_ed_sample(self, timestamp, sample):
        self._samples_queue.put(sample, block=True, timeout=None)


class MACManager(object):
    """
    This class implements the Medium Access Control Manager (MAC - defined in 802.15.4 specification).

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)

    The API is exposed by two services.
    """
    def __init__(self, stack):
        self.__stack = stack
        self.__ack_queue = Queue()
        self.__data_service = MACDataService(self)
        self.__management_service = MACManagementService(self)
        self.__pib = MACPIB()
        if conf.dot15d4_protocol == "zigbee":
            self.__upper_layer = NWKManager(self)
        else:
            self.__upper_layer = None

    @property
    def upper_layer(self):
        return self.__upper_layer

    @upper_layer.setter
    def upper_layer(self, upper_layer):
        self.__upper_layer = upper_layer

    @property
    def stack(self):
        return self.__stack

    def on_pdu(self, pdu):
        if Dot15d4Data in pdu:
            self.__data_service.on_data_pdu(pdu)
        elif pdu.fcf_frametype == 0x02 or Dot15d4Ack in pdu:
            self.__ack_queue.put(pdu, block=True, timeout=None)
        elif Dot15d4Cmd in pdu:
            self.__management_service.on_cmd_pdu(pdu)
        elif Dot15d4Beacon in pdu:
            self.__management_service.on_beacon_pdu(pdu)
        else:
            pdu.show()
    def on_ed_sample(self, timestamp, sample):
        self.__management_service.on_ed_sample(timestamp, sample)

    def notify_beacon(self, pan_descriptor, beacon_payload):
        if self.__upper_layer is not None:
            self.__upper_layer.on_beacon_pdu(pan_descriptor, beacon_payload)

    def set_channel_page(self, page):
        self.__stack.set_channel_page(page)

    def set_channel(self, channel):
        self.__stack.set_channel(channel)

    def perform_ed_scan(self, channel):
        self.__stack.perform_ed_scan(channel)

    @property
    def management_service(self):
        return self.__management_service

    @property
    def data_service(self):
        return self.__data_service

    @property
    def pib(self):
        return self.__pib

    def wait_for_ack(self, timeout=0.5):
        """Wait for a ACK or error, other messages are dropped

        :param type message_clazz: Expected message class
        :param float timeout: Timeout value (default: 30 seconds)
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.1)
                return msg
            except Empty:
                pass
        raise MACTimeoutException

    def send_data(self, packet, wait_for_ack=False):
        packet = Dot15d4()/packet
        if wait_for_ack:
            packet.fcf_ackreq = 1
        sequence_number = self.__pib.get("macDataSequenceNumber")
        packet.seqnum = sequence_number
        self.__pib.set("macDataSequenceNumber", sequence_number + 1)
        self.__stack.send(packet)
        if wait_for_ack:
            try:
                ack = self.wait_for_ack()
                print("ack", ack)
                return ack.seqnum == sequence_number
            except MACTimeoutException:
                return False
        else:
            return True

    def send_beacon(self, packet):
        packet = Dot15d4()/packet
        sequence_number = self.__pib.get("macBeaconSequenceNumber")
        packet.seqnum = sequence_number
        self.__pib.set("macBeaconSequenceNumber", sequence_number + 1)
        self.__stack.send(packet)
