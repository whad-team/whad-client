from .constants import MACScanType, MACConstants, MACAddressMode, Dot15d4PANNetwork, \
    EDMeasurement, MACDeviceType, MACPowerSource
from whad.zigbee.stack.constants import SYMBOL_DURATION
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from .exceptions import MACTimeoutException
from whad.exceptions import RequiredImplementation
from queue import Queue, Empty
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Beacon, Dot15d4Cmd, \
    Dot15d4Ack, Dot15d4, Dot15d4CmdAssocReq
from time import time,sleep
from whad.zigbee.stack.nwk import NWKManager
import logging

logger = logging.getLogger(__name__)

class MACPIB(Dot15d4Database):
    """
    802.15.4 MAC PIB Database of attributes.
    """

    def reset(self):
        """
        Reset the PIB database to its default value.
        """
        self.macExtendedAddress = None
        self.macAssociatedPanCoord = False
        self.macAssociationPermit = False
        self.macAutoRequest = False
        self.macDataSequenceNumber = 0
        self.macBeaconSequenceNumber = 0
        self.macPanId = 0xFFFF
        self.macShortAddress = 0xFFFF
        self.macCoordShortAddress = 0
        self.macCoordExtendedAddress = 0
        self.macPromiscuousMode = True
        self.macImplicitBroadcast = False


class MACService(Dot15d4Service):
    """
    This class represents a MAC service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(manager, name=name, timeout_exception_class=MACTimeoutException)


class MACDataService(MACService):
    """
    MAC service processing Data packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="mac_data")

    @Dot15d4Service.request("MCPS-DATA")
    def data(self, msdu, msdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF, pan_id_suppressed=False, sequence_number_suppressed=False, wait_for_ack=False):
        data = Dot15d4Data()
        if destination_pan_id is not None:
            data.dest_panid = destination_pan_id
        if destination_address is not None:
            data.dest_addr = destination_address
        if not pan_id_suppressed:
            data.src_panid = self.database.get("macPanId")
        if source_address_mode == MACAddressMode.SHORT:
            data.src_addr = self.database.get("macShortAddress")
        elif source_address_mode == MACAddressMode.EXTENDED:
            data.src_addr = self.database.get("macExtendedAddress")

        ack = self.manager.send_data(data, wait_for_ack=wait_for_ack)
        return ack

    def on_data_pdu(self, pdu):
        self.indicate_data(pdu)

    def on_ack_pdu(self, pdu):
        pass

    @Dot15d4Service.indication("MCPS-DATA")
    def indicate_data(self, pdu):
        source_pan_id = pdu.src_panid if hasattr(pdu, "src_panid") else None
        source_address = pdu.src_addr if hasattr(pdu, "src_addr") else None
        destination_pan_id = pdu.dest_panid if hasattr(pdu, "dest_panid") else None
        destination_address = pdu.dest_addr if hasattr(pdu, "dest_addr") else None
        payload = pdu[Dot15d4Data].payload if Dot15d4Data in pdu else pdu[Dot15d4].payload
        return {
            "pdu":payload,
            "destination_pan_id":destination_pan_id,
            "destination_address":destination_address,
            "source_pan_id":source_pan_id,
            "source_address":source_address
        }

class MACManagementService(MACService):
    """
    MAC service processing Management packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="mac_management")
        self._samples_queue = Queue()

    def add_ed_sample_to_queue(self, ed_sample):
        """
        Add an ED sample to the queue for later processing.
        """
        self._samples_queue.put(ed_sample)

    # Requests
    @Dot15d4Service.request("MLME-GET")
    def get(self, attribute):
        """
        Implement the MLME-GET request operation.
        """
        return self.database.get(attribute)

    @Dot15d4Service.request("MLME-SET")
    def set(self, attribute, value):
        """
        Implement the MLME-SET request operation.
        """
        return self.database.set(attribute, value)

    @Dot15d4Service.request("MLME-RESET")
    def reset(self, set_default_pib=True):
        """
        Implement the MLME-RESET request operation.
        """
        if set_default_pib:
            self.database.reset()
            return True
        return False

    @Dot15d4Service.request("MLME-POLL")
    def poll(self, coordinator_pan_id=0, coordinator_address=0):
        """
        Implement the MLME-POLL request operation.
        """
        ack = self.manager.send_data(
            Dot15d4Cmd(
                cmd_id="DataReq",
                dest_addr=coordinator_address,
                dest_panid=coordinator_pan_id,
                src_addr=self.database.get("macShortAddress"),
                src_panid=self.database.get("macPanId")
            ),
            wait_for_ack=True,
            return_ack=True
        )
        if ack.fcf_pending:
            try:
                data = self.manager.get_service("data").wait_for_packet(lambda pkt: Dot15d4Data in pkt or pkt.fcf_frametype == 1)
                return True
            except MACTimeoutException:
                return False
        return False

    def associate(self, channel_page=0, channel=11, coordinator_pan_id=0, coordinator_address=0, device_type=MACDeviceType.FFD, power_source=MACPowerSource.ALTERNATING_CURRENT_SOURCE, idle_receiving=True, allocate_address=True, security_capability=False, fast_association=False):
        """
        Implement the MLME-ASSOCIATE request operation.
        """
        self.manager.set_channel_page(channel_page)
        self.manager.set_channel(channel)
        #print("Channel", channel)
        acked = self.manager.send_data(
                Dot15d4Cmd(
                    cmd_id="AssocReq",
                    dest_addr=coordinator_address,
                    dest_panid=coordinator_pan_id,
                    src_addr="00:17:88:01:02:03:04:05",
                    src_panid=0xFFFF
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
            pass

    @Dot15d4Service.request("MLME-SCAN")
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
        duration = MACConstants.A_BASE_SUPERFRAME_DURATION * ((2**scan_duration) + 1) * SYMBOL_DURATION[self.manager.stack.phy]

        # Select the right scan
        if scan_type == MACScanType.ACTIVE:
            return self._perform_legacy_scan(channel_page, channels, duration, active=True)
        elif scan_type == MACScanType.PASSIVE:
            return self._perform_legacy_scan(channel_page, channels, duration, active=False)
        elif scan_type == MACScanType.ENERGY_DETECTION:
            return self._perform_ed_scan(channel_page, channels, duration)
        else:
            raise RequiredImplementation("Scan")

    # Indications
    @Dot15d4Service.indication("MLME-BEACON-NOTIFY")
    def indicate_beacon_notify(self, pan_descriptor, beacon_payload):
        return {"pan_descriptor": pan_descriptor, "beacon_payload":beacon_payload}



    # Low level primitives and helpers
    def _perform_legacy_scan(self, channel_page, channels, duration, active=True):
        pan_descriptors = []
        # Enter MAC Promiscuous mode to prevent filtering
        oldPromiscuousMode = self.database.get("macPromiscuousMode")
        self.database.set("macPromiscuousMode", True)
        for channel in channels:
            self.manager.set_channel_page(channel_page)
            self.manager.set_channel(channel)
            #print("Channel", channel)
            start_time = time()* 1000000
            if active:
                self.manager.send_data(Dot15d4Cmd(
                    cmd_id="BeaconReq",
                    dest_addr=0xFFFF,
                    dest_panid=0xFFFF)
                )

            while (time()* 1000000 - start_time) < duration:
                try:
                    beacon = self.wait_for_packet(lambda pkt: Dot15d4Beacon in pkt, timeout=0.0001)
                    pan_descriptor = Dot15d4PANNetwork(beacon, channel_page, channel)
                    self.indicate_beacon_notify(pan_descriptor, beacon[Dot15d4Beacon].payload)
                    if pan_descriptor not in pan_descriptors:
                        pan_descriptors.append(pan_descriptor)
                except MACTimeoutException:
                    pass
        self.database.set("macPromiscuousMode", oldPromiscuousMode)
        return pan_descriptors


    def _perform_ed_scan(self, channel_page, channels, duration):
        ed_measurements = []
        for channel in channels:
            self.manager.set_channel_page(channel_page)
            self._samples_queue.queue.clear()
            self.manager.perform_ed_scan(channel)

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

    # Input callbacks
    def on_cmd_pdu(self, pdu):
        pass#pdu.show()

    def on_beacon_pdu(self, pdu):
        self.add_packet_to_queue(pdu)
        macAutoRequest = self.database.get("macAutoRequest")
        if macAutoRequest:
            macPanId = self.database.get("macPanId")
            if pdu.src_panid == macPanId:
                extendedAddress = self.database.get("macExtendedAddress")
                shortAddress = self.database.get("macShortAddress")
                if (
                        extendedAddress in beacon.pa_long_addresses or
                        shortAddress in beacon.pa_short_addresses
                ):
                    self.poll(coordinator_pan_id=beacon.src_panid, coordinator_address=beacon.src_addr)

    def on_ed_sample(self, timestamp, sample):
        self.add_ed_sample_to_queue(sample)

class MACManager(Dot15d4Manager):
    """
    This class implements the Medium Access Control Manager (MAC - defined in 802.15.4 specification).

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)

    The API is exposed by two services.
    """
    def __init__(self, stack, upper_layer=None):
        super().__init__(
            services={
                        "management": MACManagementService(self),
                        "data": MACDataService(self)
            },
            database=MACPIB(),
            upper_layer=upper_layer
        )
        self.__stack = stack
        self.__ack_queue = Queue()

    @property
    def stack(self):
        return self.__stack

    @property
    def pib(self):
        return self.database

    def on_pdu(self, pdu):
        if self.match_filter(pdu):
            if pdu.fcf_frametype == 0x01 or Dot15d4Data in pdu:
                self.get_service("data").on_data_pdu(pdu)
            elif pdu.fcf_frametype == 0x02 or Dot15d4Ack in pdu:
                self.__ack_queue.put(pdu, block=True, timeout=None)
                self.get_service("data").on_ack_pdu(pdu)
            elif pdu.fcf_frametype == 0x03 or Dot15d4Cmd in pdu:
                self.get_service("management").on_cmd_pdu(pdu)
            elif pdu.fcf_frametype == 0x00 or Dot15d4Beacon in pdu:
                self.get_service("management").on_beacon_pdu(pdu)
            else:
                logger.warning("[mac_manager] Malformed PDU received: {}", repr(pdu))

    def match_filter(self, pdu):
        macPromiscuousMode = self.database.get("macPromiscuousMode")
        if macPromiscuousMode:
            return True

        macImplicitBroadcast = self.database.get("macImplicitBroadcast")
        if (
                not hasattr(pdu, "dest_panid") and
                not hasattr(pdu, "dest_addr") and
                macImplicitBroadcast
        ):
            return True

        macPanId = self.database.get("macPanId")
        if (
                not hasattr(pdu, "dest_panid") and
                not hasattr(pdu, "dest_addr") and
                hasattr(pdu, "src_panid") and
                pdu.src_panid != macPanId
        ):
            return False

        if hasattr(pdu, "dest_panid"):
            if pdu.dest_panid != macPanId and pdu.dest_panid != 0xFFFF:
                return False


        if hasattr(pdu, "dest_addr"):
            macShortAddress = self.database.get("macShortAddress")
            macExtendedAddress = self.database.get("macExtendedAddress")
            if (
                pdu.dest_addr != macShortAddress and
                pdu.dest_addr != macExtendedAddress and
                pdu.dest_addr != 0xFFFF
            ):
                return False

        return True

    def on_ed_sample(self, timestamp, sample):
        self.get_service("management").on_ed_sample(timestamp, sample)

    def set_channel_page(self, page):
        self.stack.set_channel_page(page)

    def set_channel(self, channel):
        self.stack.set_channel(channel)

    def perform_ed_scan(self, channel):
        self.stack.perform_ed_scan(channel)

    def wait_for_ack(self, timeout=0.5):
        """Wait for a ACK or error.

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

    def send_data(self, packet, wait_for_ack=False, return_ack=False):
        packet = Dot15d4()/packet
        if wait_for_ack:
            packet.fcf_ackreq = 1
        sequence_number = self.database.get("macDataSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macDataSequenceNumber", sequence_number + 1)
        self.stack.send(packet)
        if wait_for_ack:
            try:
                ack = self.wait_for_ack()
                if return_ack:
                    return ack
                return ack.seqnum == sequence_number
            except MACTimeoutException:
                if return_ack:
                    return None
                return False
        else:
            return True

    def send_beacon(self, packet):
        packet = Dot15d4()/packet
        sequence_number = self.database.get("macBeaconSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macBeaconSequenceNumber", sequence_number + 1)
        self.stack.send(packet)
