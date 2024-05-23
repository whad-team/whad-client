from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.database import MACPIB
from whad.dot15d4.stack.mac.exceptions import MACTimeoutException, MACAssociationFailure
from whad.dot15d4.stack.mac.helpers import is_short_address
from whad.dot15d4.stack.mac.constants import MACScanType, MACConstants, MACAddressMode, \
    MACDeviceType, MACPowerSource, MACBeaconType, MACAssociationStatus
from whad.dot15d4.stack.mac.network import Dot15d4PANNetwork
from whad.dot15d4.stack.mac.energy import EDMeasurement
from whad.common.stack import Layer, alias, source, state
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Beacon, Dot15d4Cmd, \
    Dot15d4Ack, Dot15d4, Dot15d4CmdAssocReq, Dot15d4CmdAssocResp
from whad.exceptions import RequiredImplementation

from threading import Thread
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

        while not self.manager.all_pending_transactions_processed(destination_address):
            sleep(0.1)

        ack = self.manager.send_data(
                                        data,
                                        wait_for_ack=wait_for_ack,
                                        source_address_mode=source_address_mode,
                                        destination_address_mode=destination_address_mode
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
        self._beaconing_thread = None
        self._beaconing_thread_enabled = False
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


    @Dot15d4Service.request("MLME-SYNC")
    def sync(
                self,
                channel_page=0,
                channel=11,
                track_beacon=False
    ):
        """
        Implement the MLME-SYNC request operation.
        """
        self.manager.set_channel_page(channel_page)
        self.manager.set_channel(channel)

        # we don't do anything according to track beacon parameter,
        # because our radio will always remain enabled.
        return True


    @Dot15d4Service.request("MLME-POLL")
    def poll(self, coordinator_pan_id=0, coordinator_address=0):
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


    @Dot15d4Service.request("MLME-BEACON")
    def beacon(
                    self,
                    beacon_type=MACBeaconType.BEACON,
                    channel_page=0,
                    channel=11,
                    superframe_order=15,
                    header_ie_list=[],
                    payload_ie_list=[],
                    header_ie_id_list=[],
                    nested_ie_sub_id_list=[],
                    beacon_security_level=0,
                    beacon_key_id_mode=0,
                    beacon_key_source=b"",
                    beacon_key_index=0,
                    source_address_mode=MACAddressMode.SHORT,
                    destination_address_mode=MACAddressMode.NONE,
                    destination_address=0xFFFF,
                    bsn_suppression=False
    ):
        if beacon_type == MACBeaconType.ENHANCED_BEACON:
            raise RequiredImplementation("EnhancedBeacon")

        src_panid = self.database.get("macPanId")
        src_addr = (
            self.database.get("macShortAddress") if
            source_address_mode == MACAddressMode.SHORT else
            self.database.get("macExtendedAddress")
        )

        sf_beaconorder = self.database.get("macBeaconOrder")
        sf_assocpermit = self.database.get("macAssociationPermit")
        is_coordinator = (
            self.database.get("macCoordShortAddress") == self.database.get("macShortAddress")
        )
        sf_battlifeextend = self.database.get("macBattLifeExt")
        beacon_payload = self.database.get("macBeaconPayload")

        beacon = Dot15d4Beacon(
            src_panid=src_panid,
            src_addr=src_addr,
            sf_sforder=superframe_order,
            sf_beaconorder=sf_beaconorder,
            sf_assocpermit=sf_assocpermit,
            sf_pancoord=is_coordinator,
            sf_battlifeextend=sf_battlifeextend
        ) / beacon_payload

        self.manager.send_beacon(
            beacon,
            source_address_mode=source_address_mode,
            destination_address_mode=destination_address_mode
        )
        return True

    @Dot15d4Service.request("MLME-START")
    def start(
                    self,
                    pan_id,
                    channel_page=0,
                    channel=11,
                    start_time=0,
                    beacon_order=15,
                    superframe_order=15,
                    pan_coordinator=True,
                    battery_life_extension=False,
                    coord_realignement=False,
                    coord_realign_security_level=0,
                    coord_realign_key_id_mode=0,
                    coord_realign_key_index=0,
                    coord_realign_key_source=b"",
                    beacon_security_level=0,
                    beacon_key_id_mode=0,
                    beacon_key_source=b"",
                    beacon_key_index=0,
                    header_ie_list=[],
                    payload_ie_list=[],
                    header_ie_id_list=[],
                    nested_ie_sub_id_list=[]
    ):
        """
        Implement the MLME-START request operation.
        """
        if coord_realignement:
            raise RequiredImplementation("CoordinatorRealignment")
        else:
            self.database.set("macBeaconOrder", 3)
            self.database.set("macSuperframeOrder", 1)
            self.database.set("macPanId", pan_id)
            self.manager.get_layer('phy').set_channel_page(channel_page)
            self.manager.get_layer('phy').set_channel(channel)


            src_panid = self.database.get("macPanId")
            src_addr = self.database.get("macShortAddress")

            sf_beaconorder = self.database.get("macBeaconOrder")
            sf_assocpermit = self.database.get("macAssociationPermit")
            is_coordinator = (
                self.database.get("macCoordShortAddress") == self.database.get("macShortAddress")
            )
            sf_battlifeextend = self.database.get("macBattLifeExt")
            beacon_payload = self.database.get("macBeaconPayload")

            beacon = Dot15d4Beacon(
                src_panid=src_panid,
                src_addr=src_addr,
                sf_sforder=superframe_order,
                sf_beaconorder=sf_beaconorder,
                sf_assocpermit=sf_assocpermit,
                sf_pancoord=is_coordinator,
                sf_battlifeextend=sf_battlifeextend
            ) / beacon_payload

            self.database.set("macLastBeacon", Dot15d4() / beacon)

            # if beaconOrder < 15, we start a beacon-enabled network
            if beacon_order < 15:
                self.database.set("macBattLifeExt", battery_life_extension)
                if pan_coordinator == False:
                    # Start beaconing after start time
                    self._start_beaconing(start_time)
                else:
                    # Start transmitting immediatly
                    self._start_beaconing()

    @Dot15d4Service.response("MLME-ASSOCIATE")
    def associate_response(
        self,
        device_address,
        assoc_short_address,
        security_level=0,
        key_id_mode=0,
        key_source=0,
        key_index=0,
        channel_offset=0,
        hopping_sequence=b"",
        dsme_association=False,
        allocation_order=0,
        bi_index=0,
        superframe_id=0,
        slot_id=0,
        channel_index=0,
        association_status=MACAssociationStatus.ASSOCIATION_SUCCESSFUL
    ):

        association_response = Dot15d4Cmd(
            cmd_id="AssocResp",
            dest_addr = device_address,
            src_addr = self.database.get("macExtendedAddress"),
            dest_panid = self.database.get("macPanId"),

        ) / Dot15d4CmdAssocResp(
            short_address = assoc_short_address,
            association_status = int(association_status)
        )

        self.manager.add_pending_transaction(
            association_response,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_address_mode=MACAddressMode.EXTENDED
        )

        # dirty, but async issue when pending transaction in use
        '''
        sleep(2)
        self.manager.send_data(
            association_response,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_address_mode=MACAddressMode.EXTENDED,
        )
        '''

        return True

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
                            self.database.set("macRxOnWhenIdle", idle_receiving)
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

    @Dot15d4Service.indication("MLME-ASSOCIATE")
    def indicate_associate(self, pdu):
        """
        Implements the MLME-ASSOCIATE indication operation.
        """
        source_address = pdu.src_addr if hasattr(pdu, "src_addr") else None
        capability_information = (
            0 |
            (int(pdu.device_type) << 1) |
            (int(pdu.power_source) << 2) |
            (int(pdu.receiver_on_when_idle) << 3) |
            (int(pdu.alternate_pan_coordinator) << 4) |
            (int(pdu.security_capability) << 6) |
            (int(pdu.allocate_address) << 7)
        )
        security_level = (
            pdu.sec_sc_seclevel if
            hasattr(pdu, "sec_sc_seclevel") and
            hasattr(pdu, "fcf_security") and
            pdu.fcf_security else
            0
        )
        key_id_mode = (
            pdu.sec_sc_keyidmode if
            hasattr(pdu, "sec_sc_keyidmode") and
            hasattr(pdu, "fcf_security") and
            pdu.fcf_security else
            0
        )
        key_source = (
            pdu.sec_keyid_keysource if
            hasattr(pdu, "sec_keyid_keysource") and
            hasattr(pdu, "fcf_security") and
            pdu.fcf_security else
            0
        )
        key_index = (
            pdu.sec_keyid_keyindex if
            hasattr(pdu, "sec_keyid_keyindex") and
            hasattr(pdu, "fcf_security") and
            pdu.fcf_security else
            0
        )
        # Default values here
        channel_offset = 0
        hopping_sequence_id = 0
        dsme_association = False
        direction = 0
        allocation_order = 0
        hopping_sequence_request = False

        return (
            source_address,
            {
                "capability_information":capability_information,
                "security_level":security_level,
                "key_id_mode":key_id_mode,
                "key_source":key_source,
                "key_index":key_index,
                "channel_offset":channel_offset,
                "hopping_sequence_id": hopping_sequence_id,
                "dsme_association":dsme_association,
                "direction":direction,
                "allocation_order": allocation_order,
                "hopping_sequence_request":hopping_sequence_request
            }
        )
    @Dot15d4Service.indication("MLME-BEACON-REQUEST")
    def indicate_beacon_request(self, pdu):
        """
        Implements the MLME-BEACON-REQUEST indication operation.
        """
        if pdu.fcf_srcaddrmode == 0:
            source_address_mode = MACAddressMode.NONE
        elif pdu.fcf_srcaddrmode == 2:
            source_address_mode = MACAddressMode.SHORT
        elif pdu.fcf_srcaddrmode == 3:
            source_address_mode = MACAddressMode.EXTENDED
        else:
            source_address_mode = MACAddressMode.NONE

        source_address = pdu.src_addr if hasattr(pdu, "src_addr") else None
        destination_pan_id = pdu.dest_panid if hasattr(pdu, "dest_panid") else 0xFFFF

        # Not processed for now, default values
        beacon_type = MACBeaconType.BEACON
        header_ie_list = []
        payload_ie_list = []
        print((beacon_type, {
                    "source_address_mode": source_address_mode,
                    "source_address": source_address,
                    "destination_pan_id": destination_pan_id,
                    "header_ie_list": header_ie_list,
                    "payload_ie_list": payload_ie_list
        })
        )
        return (beacon_type, {
                    "source_address_mode": source_address_mode,
                    "source_address": source_address,
                    "destination_pan_id": destination_pan_id,
                    "header_ie_list": header_ie_list,
                    "payload_ie_list": payload_ie_list
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

    def _start_beaconing(self, start_time=0):
        # Check if we are beacon-enabled PAN
        if self.database.get("macBeaconOrder") == 15:
            # non beacon-enabled, terminate
            return False

        beacon_interval = (
            MACConstants.A_BASE_SUPERFRAME_DURATION *
            (2**self.database.get("macBeaconOrder"))
        )

        if self.database.get("macSuperframeOrder") == 15:
            superframe = False
        else:
            superframe = True

        superframe_duration = (
            MACConstants.A_BASE_SUPERFRAME_DURATION *
            (2**self.database.get("macSuperframeOrder"))
        )

        if self._beaconing_thread is not None:
                self._stop_beaconing()

        # Waiting time before start
        init_time = time()
        while (time() - init_time) < start_time:
            pass

        self._beaconing_thread_enabled = True
        self._beaconing_thread = Thread(target=self._beaconing,args=(beacon_interval, superframe, superframe_duration), daemon=True)
        self._beaconing_thread.start()

    def _stop_beaconing(self):
        self._beaconing_thread_enabled = False
        self._beaconing_thread = None

    def _beaconing(self, beacon_interval, superframe, superframe_duration):
        """
        Thread responsible of transmitting beacon and managing superframe.
        """
        last_beacon_time = None
        in_superframe = False

        while self._beaconing_thread_enabled:
            current_time = time() * 1000
            if last_beacon_time is None or (current_time - last_beacon_time) >= beacon_interval:
                last_beacon_time = current_time
                in_superframe = True
                self.beacon()
                print("superframe opened")
            if superframe and in_superframe and (current_time - last_beacon_time) >= superframe_duration:
                in_superframe = False
                print("superframe closed")
            sleep(0.01)

    # Input callbacks
    def on_cmd_pdu(self, pdu):
        if pdu.cmd_id == 1: # Association Request
            self.indicate_associate(pdu)
        elif pdu.cmd_id == 4:
            self.on_data_request(pdu)
            self.indicate_data_req(pdu)
        elif pdu.cmd_id == 7: # Beacon Request
            if self.database.get("macBeaconAutoRespond"):
                self.beacon()
            else:
                self.indicate_beacon_request(pdu)
        self.add_packet_to_queue(pdu)

    @Dot15d4Service.indication("MLME−DATA-REQ")
    def indicate_data_req(self, pdu):
        """
        Pseudo indication for Data Request.
        """
        return (pdu, {})

    def on_data_request(self, pdu):
        """
        Callback triggered when a data request is received.

        This method will check if some pending data are available and transmit it if necessary.
        """
        pending = self.manager.get_pending_transaction(pdu.src_addr)
        if pending is not None:
            packet, source_address_mode, destination_address_mode = pending

            self.manager.send_data(
                packet,
                source_address_mode=source_address_mode,
                destination_address_mode=destination_address_mode
            )


    def on_beacon_pdu(self, pdu):
        """
        Callback triggered when a beacon is received.
        """
        self.add_packet_to_queue(pdu)
        macAutoRequest = self.database.get("macAutoRequest")
        if macAutoRequest:
            macPanId = self.database.get("macPanId")
            if pdu.src_panid == macPanId:
                # Check if some data are pending for us, and transmit a Data Request if necessary.
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
        self.__pending_transactions = {}
        # Move it to connector ?
        #self.set_extended_address(self.database.get("macExtendedAddress"))


    def all_pending_transactions_processed(self, address):
        if address in self.__pending_transactions:
            return self.__pending_transactions[address].empty()
        else:
            return True

    def add_pending_transaction(self, packet, source_address_mode=None, destination_address_mode=None):
        """
        Put outgoing data as pending.
        """
        if packet.dest_addr not in self.__pending_transactions:
            self.__pending_transactions[packet.dest_addr] = Queue()

        self.__pending_transactions[packet.dest_addr].put(
            (packet, source_address_mode, destination_address_mode)
        )

    def get_pending_transaction(self, address):
        """
        Get the latest pending transaction available.

        Return None if transaction queue is empty.
        """
        if (
            address in self.__pending_transactions and
            not self.__pending_transactions[address].empty()
        ):
            return self.__pending_transactions[address].get()
        else:
            return None

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


    def wait_for_ack(self, timeout=None):
        """Wait for a ACK or error.

        :param float timeout: Timeout value (default: 30 seconds)
        """
        if timeout is None:
            timeout = self.database.get("macAckTimeout")
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.1)
                return msg
            except Empty:
                pass
        raise MACTimeoutException

    def _choose_pan_id_compression(self, packet, destination_address_mode, source_address_mode):
        if packet.fcf_framever in (0, 1):
            if (
                destination_address_mode != MACAddressMode.NONE and
                source_address_mode != MACAddressMode.NONE
            ):

                if (
                    hasattr(packet, "dest_panid") and
                    hasattr(packet, "src_panid") and
                    packet.dest_panid == packet.src_panid
                ):
                    packet.fcf_panidcompress = 1
                else:
                    packet.fcf_panidcompress = 0
            else:
                packet.fcf_panidcompress = 0
        elif packet.fcf_framever == 2:
            framecompress = PANID_COMPRESSION_TABLE[
                (
                    destination_address_mode,
                    source_address_mode,
                    hasattr(packet, "dest_panid"),
                    hasattr(packet, "src_panid")
                )
            ]
            if (
                (
                    source_address_mode == MACAddressMode.SHORT and
                    destination_address_mode != MACAddressMode.NONE
                ) or
                (
                    destination_address_mode == MACAddressMode.SHORT and
                    source_address_mode != MACAddressMode.NONE
                )
            ):
                if (
                    hasattr(packet, "dest_panid") and
                    hasattr(packet, "src_panid") and
                    packet.dest_panid == packet.src_panid
                ):
                    packet.fcf_panidcompress = 1
                else:
                    packet.fcf_panidcompress = 0
            else:
                packet.fcf_panidcompress = framecompress
        else:
            packet.fcf_panidcompress = 0
        return packet

    def send_data(self, packet, wait_for_ack=False, return_ack=False, source_address_mode=None, destination_address_mode=None):
        if source_address_mode is not None:
            if source_address_mode == MACAddressMode.NONE:
                fcf_srcaddrmode = 0
            elif source_address_mode == MACAddressMode.SHORT:
                fcf_srcaddrmode = 2
            else:
                fcf_srcaddrmode = 3
        else:
            source_address_mode = MACAddressMode.NONE
            fcf_srcaddrmode = 0

        if destination_address_mode is not None:
            if destination_address_mode == MACAddressMode.NONE:
                fcf_destaddrmode = 0
            elif destination_address_mode == MACAddressMode.SHORT:
                fcf_destaddrmode = 2
            else:
                fcf_destaddrmode = 3
        else:
            destination_address_mode = MACAddressMode.SHORT
            fcf_destaddrmode = 2

        packet = Dot15d4(
                    fcf_srcaddrmode=fcf_srcaddrmode,
                    fcf_destaddrmode=fcf_destaddrmode
        )/packet

        if wait_for_ack:
            packet.fcf_ackreq = 1

        # Build PAN ID compression field
        packet = self._choose_pan_id_compression(packet, destination_address_mode, source_address_mode)

        #    packet.fcf_panidcompress = 1

        sequence_number = self.database.get("macDataSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macDataSequenceNumber", sequence_number + 1)
        self.send('phy', packet, tag='pdu')
        wait_counter = 5
        if wait_for_ack:
            ack = None
            while ack is None or ack.seqnum != sequence_number:
                try:
                    ack = self.wait_for_ack()
                except MACTimeoutException:
                    wait_counter = wait_counter - 1
                    if wait_counter <= 0:
                        if return_ack:
                            return None
                        return False
            if return_ack:
                return ack
            return True
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

    def send_beacon(self, packet, source_address_mode=None, destination_address_mode=None):
        if source_address_mode is not None:
            if source_address_mode == MACAddressMode.NONE:
                fcf_srcaddrmode = 0
            elif source_address_mode == MACAddressMode.SHORT:
                fcf_srcaddrmode = 2
            else:
                fcf_srcaddrmode = 3
        else:
            source_address_mode = MACAddressMode.NONE
            fcf_srcaddrmode = 0

        if destination_address_mode is not None:
            if destination_address_mode == MACAddressMode.NONE:
                fcf_destaddrmode = 0
            elif destination_address_mode == MACAddressMode.SHORT:
                fcf_destaddrmode = 2
            else:
                fcf_destaddrmode = 3
        else:
            destination_address_mode = MACAddressMode.NONE
            fcf_destaddrmode = 2

        packet = Dot15d4(
                    fcf_srcaddrmode=fcf_srcaddrmode,
                    fcf_destaddrmode=fcf_destaddrmode
        )/packet

        # Build PAN ID compression field
        packet = self._choose_pan_id_compression(packet, destination_address_mode, source_address_mode)

        sequence_number = self.database.get("macBeaconSequenceNumber")
        packet.seqnum = sequence_number
        self.database.set("macBeaconSequenceNumber", sequence_number + 1)
        self.send('phy', packet, tag='pdu')
