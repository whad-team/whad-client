from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.database import MACPIB
from whad.dot15d4.stack.mac.exceptions import MACTimeoutException, MACAssociationFailure
from whad.dot15d4.stack.mac.helpers import is_short_address
from whad.dot15d4.stack.mac.constants import MACScanType, MACConstants, MACAddressMode, \
    MACDeviceType, MACPowerSource
from whad.dot15d4.stack.mac.network import Dot15d4PANNetwork
from whad.dot15d4.stack.mac.energy import EDMeasurement
from whad.common.stack import Layer, alias, source, state
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Beacon, Dot15d4Cmd, \
    Dot15d4Ack, Dot15d4, Dot15d4CmdAssocReq, Dot15d4CmdAssocResp
from whad.exceptions import RequiredImplementation

from time import time, sleep
from queue import Queue, Empty

import logging

logger = logging.getLogger(__name__)



class MACService(Dot15d4Service):
    """
    This class represents a MAC service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(
            manager,
            name=name,
            timeout_exception_class=MACTimeoutException
        )

class MACDataService(MACService):
    """
    MAC service processing Data packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="mac_data")


    @Dot15d4Service.request("MCPS-DATA")
    def data(
                self,
                msdu,
                msdu_handle=0,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=0xFFFF,
                destination_address=0xFFFF,
                destination_address_mode=MACAddressMode.SHORT,
                pan_id_suppressed=False,
                pan_id_compress=False,
                sequence_number_suppressed=False,
                wait_for_ack=False
    ):

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
        data = data/msdu


        ack = self.manager.send_data(
                                        data,
                                        wait_for_ack=wait_for_ack,
                                        source_address_mode=source_address_mode,
                                        destination_address_mode=destination_address_mode,
                                        pan_id_compress=pan_id_compress
        )
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
        link_quality = pdu.metadata.lqi if hasattr(pdu, "metadata") and hasattr(pdu.metadata, "lqi") else 255
        return (payload, {
            "destination_pan_id":destination_pan_id,
            "destination_address":destination_address,
            "source_pan_id":source_pan_id,
            "source_address":source_address,
            "link_quality":link_quality
        })


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
            self.manager.set_extended_address(self.database.get("macExtendedAddress"))
            return True
        return False

    @Dot15d4Service.request("MLME-POLL")
    def poll(self, coordinator_pan_id=0, coordinator_address=0, pan_id_compress=False):
        """
        Implement the MLME-POLL request operation.
        """
        ack = self.manager.send_data(
            Dot15d4Cmd(
                cmd_id = "DataReq",
                dest_addr = coordinator_address,
                dest_panid = coordinator_pan_id,
                src_addr = self.database.get("macShortAddress"),
                src_panid = self.database.get("macPanId")
            ),
            wait_for_ack=True,
            return_ack=True,
            pan_id_compress=pan_id_compress,
            source_address_mode=MACAddressMode.SHORT,
            destination_address_mode=MACAddressMode.SHORT,
        )
        if ack is None:
            return False
        if ack.fcf_pending:
            try:
                data = self.manager.get_service("data").wait_for_packet(
                    lambda pkt: Dot15d4Data in pkt or pkt.fcf_frametype == 1
                )
                return True
            except MACTimeoutException:
                return False
        return False

    @Dot15d4Service.request("MLME-ASSOCIATE")
    def associate(
                    self,
                    channel_page=0,
                    channel=11,
                    coordinator_pan_id=0,
                    coordinator_address=0,
                    device_type=MACDeviceType.FFD,
                    power_source=MACPowerSource.ALTERNATING_CURRENT_SOURCE,
                    idle_receiving=True,
                    allocate_address=True,
                    security_capability=False,
                    fast_association=False
    ):
        """
        Implement the MLME-ASSOCIATE request operation.
        """
        self.database.set("macPanId", coordinator_pan_id)
        if is_short_address(coordinator_address):
            self.database.set("macCoordShortAddress", coordinator_address)
        else:
            self.database.set("macCoordExtendedAddress", coordinator_address)
        self.manager.set_channel_page(channel_page)
        self.manager.set_channel(channel)

        duration = (
            self.database.get("macResponseWaitTime") *
            MACConstants.A_BASE_SUPERFRAME_DURATION *
            self.manager.get_layer('phy').symbol_duration
        )

        try:
            acked = self.manager.send_data(
                    Dot15d4Cmd(
                        cmd_id = "AssocReq",
                        dest_addr = coordinator_address,
                        dest_panid = coordinator_pan_id,
                        src_addr = self.database.get("macExtendedAddress"),
                        src_panid = 0xFFFF
                    )/
                    Dot15d4CmdAssocReq(
        				allocate_address = int(allocate_address),
        				security_capability = int(security_capability),
        				power_source = int(power_source == MACPowerSource.ALTERNATING_CURRENT_SOURCE),
        				device_type = int(device_type == MACDeviceType.FFD),
        				receiver_on_when_idle = int(idle_receiving),
        				alternate_pan_coordinator = int(fast_association)
        		  )
                ,
                wait_for_ack=True,
                source_address_mode=MACAddressMode.EXTENDED
            )

            if acked:
                sleep(duration/1000000)
                ack = self.manager.send_data(
                    Dot15d4Cmd(
                        cmd_id = "DataReq",
                        dest_addr = coordinator_address,
                        dest_panid = coordinator_pan_id,
                        src_addr = self.database.get("macExtendedAddress"),
                        src_panid = 0xFFFF
                    ),
                    wait_for_ack=True,
                    source_address_mode=MACAddressMode.EXTENDED
                )

                if acked:
                    try:
                        association_response = self.wait_for_packet(
                            lambda pkt: Dot15d4CmdAssocResp in pkt, timeout=5.0
                        )
                        if association_response.association_status == 0:
                            self.manager.set_short_address(association_response.short_address)
                            if association_response.fcf_srcaddrmode == 2:
                                self.database.set("macCoordShortAddress", association_response.src_addr)
                            elif association_response.fcf_srcaddrmode == 3:
                                self.database.set("macCoordExtendedAddress", association_response.src_addr)

                            return True
                        else:
                            raise MACAssociationFailure("association response unsuccessful (status={})".format(hex(association_response.association_status)))
                    except MACTimeoutException:
                        raise MACAssociationFailure("association response timeout. ")
                else:
                    raise MACAssociationFailure("no acknowledgement received for DataRequest. ")
            else:
                raise MACAssociationFailure("no acknowledgement received for AssociationRequest. ")

        except MACAssociationFailure as err:
            logger.info("[{}] Association failure - {}. ".format(self._name, err.reason))
            self.database.set("macPanId", 0xFFFF)
            return False


    @Dot15d4Service.request("MLME-SCAN")
    def scan(
                self,
                scan_type=MACScanType.ACTIVE,
                channel_page=0,
                scan_channels=0x7fff800,
                scan_duration=5
    ):
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
        duration = (
            MACConstants.A_BASE_SUPERFRAME_DURATION *
            ((2**scan_duration) + 1) *
            self.manager.get_layer('phy').symbol_duration
        )

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
        return (beacon_payload, {
                    "pan_descriptor": pan_descriptor,
        })

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
            start_time = time()
            if active:
                self.manager.send_data(
                    Dot15d4Cmd(
                        cmd_id="BeaconReq",
                        dest_addr=0xFFFF,
                        dest_panid=0xFFFF
                    )
                )

            while (time() - start_time) < duration:
                try:
                    beacon = self.wait_for_packet(
                        lambda pkt: Dot15d4Beacon in pkt, timeout=0.0001
                    )
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

            start_time = time()
            samples = []
            while (time() - start_time) < duration:
                try:
                    sample = self._samples_queue.get(block=False)
                    samples.append(sample)
                except Empty:
                    pass
            ed_measurements.append(EDMeasurement(samples, channel_page, channel))
        return ed_measurements

    # Input callbacks
    def on_cmd_pdu(self, pdu):
        self.add_packet_to_queue(pdu)

    def on_beacon_pdu(self, pdu):
        self.add_packet_to_queue(pdu)
        macAutoRequest = self.database.get("macAutoRequest")
        if macAutoRequest:
            macPanId = self.database.get("macPanId")
            if pdu.src_panid == macPanId:
                extendedAddress = self.database.get("macExtendedAddress")
                shortAddress = self.database.get("macShortAddress")
                if (
                        extendedAddress in pdu.pa_long_addresses or
                        shortAddress in pdu.pa_short_addresses
                ):
                    self.poll(coordinator_pan_id=pdu.src_panid, coordinator_address=pdu.src_addr)

    def on_ed_sample(self, timestamp, sample):
        self.add_ed_sample_to_queue(sample)


@state(MACPIB)
@alias('mac')
class MACManager(Dot15d4Manager):
    """
    This class implements the Medium Access Control Manager (MAC - defined in 802.15.4 specification).

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)

    The API is exposed by two services.
    """
    def init(self):
        self.add_service("data", MACDataService(self))
        self.add_service("management", MACManagementService(self))
        self.__ack_queue = Queue()
        # Move it to connector ?
        #self.set_extended_address(self.database.get("macExtendedAddress"))


    @source('phy', 'energy_detection')
    def on_ed_sample(self, sample, timestamp):
        self.get_service("management").on_ed_sample(timestamp, sample)

    @source('phy', 'pdu')
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
                logger.warning("[mac_manager] Malformed PDU received: {}".format(repr(pdu)))

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


    def wait_for_ack(self, timeout=0.3):
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

    def send_data(self, packet, wait_for_ack=False, return_ack=False, source_address_mode=None, destination_address_mode=None, pan_id_compress=False):
        if source_address_mode is not None:
            if source_address_mode == MACAddressMode.NONE:
                fcf_srcaddrmode = 0
            elif source_address_mode == MACAddressMode.SHORT:
                fcf_srcaddrmode = 2
            else:
                fcf_srcaddrmode = 3
        else:
            fcf_srcaddrmode = 0

        if destination_address_mode is not None:
            if destination_address_mode == MACAddressMode.NONE:
                fcf_destaddrmode = 0
            elif destination_address_mode == MACAddressMode.SHORT:
                fcf_destaddrmode = 2
            else:
                fcf_destaddrmode = 3
        else:
            fcf_destaddrmode = 2

        packet = Dot15d4(
                    fcf_srcaddrmode=fcf_srcaddrmode,
                    fcf_destaddrmode=fcf_destaddrmode
        )/packet

        if wait_for_ack:
            packet.fcf_ackreq = 1
        if pan_id_compress:
            packet.fcf_panidcompress = 1
        sequence_number = self.database.get("macDataSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macDataSequenceNumber", sequence_number + 1)
        self.send('phy', packet, tag='pdu')
        if wait_for_ack:
            try:
                ack = None
                while ack is None or ack.seqnum != sequence_number:
                    ack = self.wait_for_ack()
                if return_ack:
                    return ack
                return True
            except MACTimeoutException:
                if return_ack:
                    return None
                return False
        else:
            return True

    def set_short_address(self, address):
        self.database.set("macShortAddress", address)
        self.get_layer('phy').set_short_address(address)

    def set_extended_address(self, address):
        self.database.set("macExtendedAddress", address)
        self.get_layer('phy').set_extended_address(address)

    def set_channel_page(self, page):
        self.get_layer('phy').set_channel_page(page)

    def set_channel(self, channel):
        self.get_layer('phy').set_channel(channel)

    def perform_ed_scan(self, channel):
        self.get_layer('phy').perform_ed_scan(channel)

    def send_beacon(self, packet):
        packet = Dot15d4()/packet
        sequence_number = self.database.get("macBeaconSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macBeaconSequenceNumber", sequence_number + 1)
        self.send('phy', packet, tag='pdu')

'''
@alias('nwk')
class NWKManager(Dot15d4Manager):

    @source('mac', 'TEST')
    def on_test(self, pdu, a, b, c):
        print(pdu)
        print("a = ", a)
        print("b = ", b)
        print("c = ", c)
'''


#MACManager.add(NWKManager)
