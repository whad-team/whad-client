from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.constants import MACAddressMode, MACScanType, \
    MACDeviceType, MACPowerSource, MACConstants, MACAssociationStatus
from whad.dot15d4.stack.mac.network import Dot15d4PANNetwork

from whad.zigbee.stack.nwk.exceptions import NWKTimeoutException, NWKInvalidKey
from whad.zigbee.stack.nwk.database import NWKIB
from whad.zigbee.stack.nwk.neighbors import NWKNeighborTable
from whad.zigbee.stack.nwk.security import NetworkSecurityMaterial
from whad.zigbee.stack.nwk.network import ZigbeeNetwork
from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType, NWKAddressMode, \
    NWKJoinMode, ZigbeeRelationship, BROADCAST_ADDRESSES

from whad.zigbee.stack.aps import APSManager

from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.common.stack import Layer, alias, source, state
from whad.exceptions import RequiredImplementation

from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWKStub, ZigbeeNWK, \
    ZigbeeSecurityHeader, ZigbeeNWKCommandPayload, ZigbeeAppDataPayload, \
    ZigbeeAppDataPayloadStub, LinkStatusEntry
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, NewZigbeeAppDataPayloadStub

from random import randint
from scapy.fields import FlagValueIter

from time import time, sleep
import logging

logger = logging.getLogger(__name__)

class NWKService(Dot15d4Service):
    """
    This class represents a NWK service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(
            manager,
            name=name,
            timeout_exception_class=NWKTimeoutException
        )


class NWKDataService(NWKService):
    """
    NWK service processing Data packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_data")

    @Dot15d4Service.request("NLDE-DATA")
    def data(
        self,
        nsdu,
        nsdu_handle=0,
        alias_address=None,
        alias_sequence_number=0,
        destination_address_mode=NWKAddressMode.UNICAST,
        destination_address=0xFFFF,
        radius=0,
        non_member_radius=7,
        discover_route=False,
        security_enable=False
    ):
        """
        Request allowing to transmit NSPDU to MAC layer.
        """
        if alias_address is not None:
            source_address = alias_address
            sequence_number = alias_sequence_number
        else:
            source_address = self.manager.get_layer('mac').get_service("management").get("macShortAddress")
            sequence_number = self.database.get("nwkSequenceNumber")
            self.database.set("nwkSequenceNumber", sequence_number+1)

        if radius == 0:
            radius = self.database.get("nwkMaxDepth") * 2

        flags = []
        if destination_address_mode == NWKAddressMode.MULTICAST:
            flags.append("multicast")
            raise RequiredImplementation("Routing/Multicasting")

        npdu = ZigbeeNWK(
            discover_route=int(discover_route),
            seqnum=sequence_number,
            radius=radius,
            flags=flags,
            destination=destination_address,
            source=source_address
        )
        if destination_address in BROADCAST_ADDRESSES.keys():
            destination_pan_id = self.database.get("nwkPANId")
            acknowledged = False
        else:
            destination_pan_id = self.database.get("nwkPANId")
            acknowledged = True

        if self.database.get("nwkSecurityLevel") != 0 and security_enable:
            npdu.flags.security = True
            selected_key_material = None

            security_material_set = self.database.get("nwkSecurityMaterialSet")
            for key_material in security_material_set:
                if key_material.key_sequence_number == self.database.get("nwkActiveKeySeqNumber"):
                    selected_key_material = key_material
                    break

            if selected_key_material is None:
                return False

            msdu = npdu / ZigbeeSecurityHeader(
                nwk_seclevel = self.database.get("nwkSecurityLevel"),
                source = self.database.get("nwkIeeeAddress"),
                key_type=1,
                key_seqnum=self.database.get("nwkActiveKeySeqNumber"),
                fc=selected_key_material.outgoing_frame_counter,
                data=bytes(nsdu)
            )
            crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
            msdu = crypto_manager.encrypt(msdu)
            selected_key_material.outgoing_frame_counter += 1
        else:
            msdu = npdu / nsdu

        return self.manager.get_layer('mac').get_service("data").data(
                    msdu,
                    msdu_handle=0,
                    source_address_mode=MACAddressMode.SHORT,
                    destination_pan_id=destination_pan_id,
                    destination_address=destination_address,
                    pan_id_suppressed=False,
                    sequence_number_suppressed=False,
                    wait_for_ack=acknowledged
        )


    def on_data_npdu(self, npdu, link_quality=255):
        """
        Callback processing NPDU from NWK manager.

        It forwards the NPDU to indicate_data method.
        """
        self.indicate_data(npdu, link_quality=link_quality)

    @Dot15d4Service.indication("NLDE-DATA")
    def indicate_data(self, npdu, link_quality=255):
        """
        Indication transmitting NPDU to upper layer.
        """
        destination_address_mode = (
            NWKAddressMode.MULTICAST if "multicast" in npdu.flags else
            NWKAddressMode.UNICAST
        )
        destination_address = npdu.destination
        source_address = npdu.source
        security_use = ZigbeeSecurityHeader in npdu and npdu[ZigbeeSecurityHeader].underlayer.__class__ is ZigbeeNWK
        if security_use:
            nsdu = ZigbeeAppDataPayload(npdu.data)
        else:
            nsdu = npdu[ZigbeeAppDataPayload]

        return (
            nsdu, {
                "destination_address_mode":destination_address_mode,
                "destination_address":destination_address,
                "source_address":source_address,
                "security_use":security_use,
                "link_quality":link_quality
            }
        )


class NWKManagementService(NWKService):
    """
    NWK service processing Management packets.
    """
    def __init__(self, manager):
        self.joining_thread_running = False
        self.joining_thread = None
        super().__init__(manager, name="nwk_management")


    @Dot15d4Service.request("NLME-RESET")
    def reset(self, warm_start=False):
        """
        Request resetting NWK layer to default state.
        """
        if warm_start:
            self.database.set("nwkNeighborTable",NWKNeighborTable())
            self.database.set("nwkRouteTable",[])
            return True
        else:
            confirm = self.manager.get_layer('mac').get_service("management").reset(set_default_pib=True)
            if confirm:
                self.database.reset()
                return True
        return False


    @Dot15d4Service.request("NLME-GET")
    def get(self, attribute):
        """
        Implement the NLME-GET request operation.

        Allows to get access to an attribute value stored in NWIB database.
        """
        return self.database.get(attribute)

    @Dot15d4Service.request("NLME-SET")
    def set(self, attribute, value):
        """
        Implement the NLME-SET request operation.

        Allows to set value to an attribute stored in NWIB database.
        """
        return self.database.set(attribute, value)


    @Dot15d4Service.request("NLME-ED-SCAN")
    def ed_scan(self, scan_channels=0x7fff800, scan_duration=2):
        """
        Implements the NLME-ED-SCAN request.

        Allows to perform an Energy Detection scan.
        """
        confirm = self.manager.get_layer('mac').get_service("management").scan(
            scan_type=MACScanType.ENERGY_DETECTION,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )
        return confirm


    @Dot15d4Service.request("NLME-LEAVE")
    def leave(self, device_address=None, remove_children=False, rejoin=True):
        """
        Implements the NLME-LEAVE request.

        Allows to leave a ZigBee network.
        """
        network_address = self.database.get("nwkNetworkAddress")
        if network_address == 0xFFFF:
            # We are not present in the network, exit the procedure
            return False

        if device_address is None or device_address == self.database.get("nwkIeeeAddress"):
            parent = self.database.get("nwkNeighborTable").get_parent()
            if parent is None:
                return False

            sequence_number = self.database.get("nwkSequenceNumber")
            self.database.set("nwkSequenceNumber", sequence_number+1)

            # We are exiting the network, build the leave command
            leave_command = ZigbeeNWK(
                frametype=1,
                seqnum=sequence_number,
                destination=parent.address,
                source=network_address,
            )/ZigbeeNWKCommandPayload(
                cmd_identifier=4,
                remove_children=int(remove_children),
                request=1,
                rejoin=int(rejoin)
            )
            self.manager.get_layer('mac').get_service("data").data(
                leave_command,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=parent.pan_id,
                destination_address=parent.address,
                wait_for_ack=False
            )
            return True


    @Dot15d4Service.request("NLME-JOIN")
    def join(self, extended_pan_id, association_type=NWKJoinMode.NEW_JOIN, scan_channels=0x7fff800, scan_duration=4, join_as_router=False, rx_on_when_idle=True, mains_powered_device=False, security_enable=False):
        """
        Implements the NLME-JOIN request.

        Allows to join or rejoin a ZigBee network.
        """
        # In case of new join
        if association_type == NWKJoinMode.NEW_JOIN:
            # Try successively available neighbors that can be considered potential parents
            table = self.database.get("nwkNeighborTable")
            while True:
                candidate_parents = table.select_suitable_parent(extended_pan_id, self.database.get("nwkUpdateId"))
                if len(candidate_parents) == 0:
                    return False

                selected_parent = candidate_parents[0]
                for candidate_parent in candidate_parents[1:]:
                    if candidate_parent.depth < selected_parent.depth:
                        selected_parent = candidate_parent

                self.database.set("nwkParentInformation", 0)

                device_type = (
                    MACDeviceType.FFD if
                    join_as_router else
                    MACDeviceType.RFD
                )
                power_source = (
                    MACPowerSource.ALTERNATING_CURRENT_SOURCE if
                    mains_powered_device else
                    MACPowerSource.BATTERY_SOURCE
                )

                capability_information = (
                    0 |
                    (int(join_as_router) << 1) |
                    (int(mains_powered_device) << 2) |
                    (int(rx_on_when_idle) << 3) |
                    (0 << 4) |
                    (0 << 6) |
                    (1 << 7)
                )
                self.database.set("nwkCapabilityInformation", capability_information)
                # Trigger an association at the MAC layer
                if self.manager.get_layer('mac').get_service("management").associate(
                    channel_page=0,
                    channel=selected_parent.logical_channel,
                    coordinator_pan_id=selected_parent.pan_id,
                    coordinator_address=selected_parent.address,
                    device_type=device_type,
                    power_source=power_source,
                    idle_receiving=rx_on_when_idle,
                    allocate_address=True,
                    security_capability=False,
                    fast_association=False
                ):
                    # Update database according to successful association
                    macShortAddress = self.manager.get_layer('mac').database.get("macShortAddress")
                    self.database.set("nwkNetworkAddress", macShortAddress)
                    self.database.set("nwkUpdateId", selected_parent.update_id)
                    self.database.set("nwkPANId", selected_parent.pan_id)
                    self.database.set("nwkExtendedPANID", extended_pan_id)
                    selected_parent.relationship = ZigbeeRelationship.IS_PARENT
                    if selected_parent.extended_address is not None and selected_parent.address is not None:
                        nwkAddressMap = self.database.get("nwkAddressMap")
                        nwkAddressMap[selected_parent.extended_address] = selected_parent.address
                    return True
                else:
                    selected_parent.potential_parent = 0

        # In the case of a rejoin
        elif association_type == NWKJoinMode.REJOIN:
            # Check if we need to allocate a new address
            if self.database.get("nwkNetworkAddress") != 0xFFFF:
                network_address = self.database.get("nwkNetworkAddress")
                allocate_address = False
            else:
                network_address = randint(1,0xFFF0) if self.database.get("nwkNetworkAddress") == 0xFFFF else self.database.get("nwkNetworkAddress")
                allocate_address = False

            if self.database.get("nwkAddrAlloc") == 2:
                allocate_address = False

            # Perform a network discovery to infer surounding networks
            candidate_zigbee_networks  = self.network_discovery(
                scan_channels=scan_channels,
                scan_duration=scan_duration
            )
            selected_zigbee_network = None
            # Select the zigbee network according to provided extended PAN ID
            for candidate_zigbee_network in candidate_zigbee_networks:
                if candidate_zigbee_network.extended_pan_id == extended_pan_id:
                    selected_zigbee_network = candidate_zigbee_network
                    break

            if selected_zigbee_network is None:
                return False

            # Select the right channel accordingly
            self.manager.get_layer('mac').set_channel_page(0)
            self.manager.get_layer('mac').set_channel(selected_zigbee_network.channel)
            table = self.database.get("nwkNeighborTable")
            while True:
                candidate_parents = table.select_suitable_parent(
                    extended_pan_id,
                    self.database.get("nwkUpdateId"),
                    no_permit_check=True
                )
                if len(candidate_parents) == 0:
                    return False
                selected_parent = candidate_parents[0]
                for candidate_parent in candidate_parents[1:]:
                    if candidate_parent.depth < selected_parent.depth:
                        selected_parent = candidate_parent

                self.database.set("nwkParentInformation", 0)

                device_type = (
                                MACDeviceType.FFD if
                                join_as_router else
                                MACDeviceType.RFD
                )
                power_source = (
                    MACPowerSource.ALTERNATING_CURRENT_SOURCE if
                    mains_powered_device else
                    MACPowerSource.BATTERY_SOURCE
                )

                capability_information = (
                    0 |
                    (int(join_as_router) << 1) |
                    (int(mains_powered_device) << 2) |
                    (int(rx_on_when_idle) << 3) |
                    (0 << 4) |
                    (0 << 6) |
                    (1 << 7)
                )
                self.database.set("nwkCapabilityInformation", capability_information)

                radius = self.database.get("nwkMaxDepth") * 2

                sequence_number = self.database.get("nwkSequenceNumber")
                self.database.set("nwkSequenceNumber", sequence_number+1)

                # Build rejoin request
                npdu = ZigbeeNWK(
                    frametype=1,
                    discover_route=0,
                    seqnum=sequence_number,
                    radius=radius,
                    flags=["extended_src"], #, "extended_dst"],
                    destination=selected_parent.address,
                    source=network_address,
                    #ext_dst=selected_parent.extended_address, # ?
                    ext_src=self.database.get("nwkIeeeAddress")
                )
                nsdu = ZigbeeNWKCommandPayload(
                    cmd_identifier=6,
                    allocate_address=int(1),
                    security_capability=False,
                    receiver_on_when_idle=int(rx_on_when_idle),
                    power_source=int(power_source),
                    device_type=int(device_type),
                    alternate_pan_coordinator=0
                )


                if self.database.get("nwkSecurityLevel") != 0 and security_enable:
                    npdu.flags.security = True
                    selected_key_material = None

                    security_material_set = self.database.get("nwkSecurityMaterialSet")
                    for key_material in security_material_set:
                        if key_material.key_sequence_number == self.database.get("nwkActiveKeySeqNumber"):
                            selected_key_material = key_material
                            break

                    if selected_key_material is None:
                        return False

                    msdu = npdu / ZigbeeSecurityHeader(
                        nwk_seclevel = self.database.get("nwkSecurityLevel"),
                        source = self.database.get("nwkIeeeAddress"),
                        key_type=1,
                        key_seqnum=self.database.get("nwkActiveKeySeqNumber"),
                        fc=selected_key_material.outgoing_frame_counter,
                        data=bytes(nsdu)
                    )
                    crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
                    msdu = crypto_manager.encrypt(msdu)
                    selected_key_material.outgoing_frame_counter += 1
                else:
                    msdu = npdu / nsdu

                self.manager.get_layer('mac').get_service("data").data(
                    msdu,
                    destination_address_mode=MACAddressMode.SHORT,
                    source_address_mode=MACAddressMode.SHORT,
                    destination_pan_id=selected_parent.pan_id,
                    destination_address=selected_parent.address,
                    wait_for_ack=True
                )
                duration = (
                            self.manager.get_layer('mac').database.get("macResponseWaitTime") *
                            MACConstants.A_BASE_SUPERFRAME_DURATION *
                            self.manager.get_layer('phy').symbol_duration
                )
                self.manager.get_layer('mac').database.set("macPanId", selected_parent.pan_id)

                self.manager.get_layer('mac').get_service('management').poll(
                    coordinator_pan_id=selected_parent.pan_id,
                    coordinator_address=selected_parent.address
                )

                rejoin_response = None
                try:
                    rejoin_response = self.wait_for_packet(
                        lambda pkt:ZigbeeNWKCommandPayload in pkt and pkt.cmd_identifier==7,
                        timeout=3
                    )
                except NWKTimeoutException:
                    selected_parent.potential_parent = 0

                if rejoin_response is not None and rejoin_response.rejoin_status == 0:
                    self.database.set("nwkNetworkAddress", rejoin_response.network_address)
                    self.manager.get_layer('mac').database.set(
                        "macShortAddress",
                        rejoin_response.network_address
                    )
                    self.database.set("nwkUpdateId", selected_parent.update_id)
                    self.database.set("nwkPANId", selected_parent.pan_id)
                    self.database.set("nwkExtendedPANID", extended_pan_id)
                    selected_parent.relationship = ZigbeeRelationship.IS_PARENT
                    if selected_parent.extended_address is not None and selected_parent.address is not None:
                        nwkAddressMap = self.database.get("nwkAddressMap")
                        nwkAddressMap[selected_parent.extended_address] = selected_parent.address
                    return True
                else:
                    selected_parent.potential_parent = 0

    @Dot15d4Service.indication("NLME-JOIN")
    def indicate_join(self, network_address, extended_address, capability_information, rejoin=False, secure_rejoin=False):

        return (
            network_address,
            {
                "extended_address":extended_address,
                "capability_information":capability_information,
                "rejoin":rejoin,
                "secure_rejoin":secure_rejoin
            }
        )
    @Dot15d4Service.request("NLME-NETWORK-DISCOVERY")
    def network_discovery(self, scan_channels=0x7fff800, scan_duration=6):
        """
        Implements the NLME-NETWORK-DISCOVERY request.

        Allows to discover a network.
        """
        confirm = self.manager.get_layer('mac').get_service("management").scan(
            scan_type=MACScanType.ACTIVE,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )

        zigbee_networks = []
        notifications_left = True
        while notifications_left:
            try:
                beacon = self.wait_for_packet(lambda pkt:ZigBeeBeacon in pkt, timeout=0.1)

                if beacon.pan_descriptor in confirm:
                    network = ZigbeeNetwork(beacon)
                    if network not in zigbee_networks:
                        zigbee_networks.append(network)

            except NWKTimeoutException:
                notifications_left = False
        return zigbee_networks

    @Dot15d4Service.request("NLME-PERMIT-JOINING")
    def permit_joining(self, duration=0xFF):
        self._stop_joining_timeout()
        if duration == 0:
            self.manager.get_layer("mac").database.set("macAssociationPermit", False)
            return True
        elif duration == 0xFF:
            self.manager.get_layer("mac").database.set("macAssociationPermit", True)
            return True
        else:
            self.manager.get_layer("mac").database.set("macAssociationPermit", True)
            self._start_joining_timeout(duration)
            return True

    def _stop_joining_timeout(self):
        self.joining_thread_running = False
        self.joining_thread = None

    def _start_joining_timeout(self, duration):
        self.joining_thread_running = True
        self.joining_thread = Thread(target=self._joining_timeout, args=(duration, ), daemon=True)
        self.joining_thread.start()

    def _joining_timeout(self, duration):
        starting_time = time()
        while self.joining_thread_running and (time() - starting_time) < duration:
            sleep(0.1)
        # Turn off joining timeout
        self.manager.get_layer("mac").database.set("macAssociationPermit", False)

    @Dot15d4Service.request("NLME-NETWORK-FORMATION")
    def network_formation(
                            self,
                            pan_id=None,
                            channel=None,
                            scan_channels=0x7fff800,
                            scan_duration=4,
                            beacon_order=15,
                            superframe_order=15,
                            battery_life_extension=False,
                            distributed_network=False,
                            distributed_network_address=0x0001
    ):
        """
        Implements the NLME-NETWORK-FORMATION request.
        """
        if distributed_network:
            raise RequiredImplementation("DistributedNetworkFormation")

        # Select the best channel according to an Energy Detection scan
        ed_reports = self.ed_scan(
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )

        print("[i] channel measurement")
        if channel is None:
            minimal_measurement = None
            for ed_report in ed_reports:
                if (
                    minimal_measurement is None or
                    minimal_measurement.max_sample > ed_report.max_sample
                ):
                    minimal_measurement = ed_report

            best_channel = minimal_measurement.channel_number
        else:
            best_channel = channel

        print("[i] active scan")
        if pan_id is None:
            # Perform an active scan to prevent the use of already in use PAN ID
            active_scan_reports = self.network_discovery(
                scan_channels=scan_channels,
                scan_duration=scan_duration
            )

            # Pick a PAN ID which is not already in use
            active_networks_pan_ids = [network.dot15d4_pan_network.coord_pan_id for network in active_scan_reports]

            selected_pan_id = randint(1,0xFFFD)
            while selected_pan_id in active_networks_pan_ids:
                selected_pan_id = randint(1,0xFFFD)
        else:
            selected_pan_id = pan_id

        self.manager.get_layer('mac').set_channel_page(0)
        self.manager.get_layer('mac').set_channel(best_channel)

        # Select network address
        if not distributed_network:
            network_address = 0x0000
        else:
            network_address = distributed_network_address

        # Espressif hijack coord: self.database.set("nwkExtendedPANID", 0x6055f90000f714e4)
        # Update the mac layer with the selected address

        self.manager.get_layer('mac').set_short_address(network_address)
        self.database.set("nwkNetworkAddress", network_address)


        if self.database.get("nwkExtendedPANID") == 0:

            self.database.set(
                "nwkExtendedPANID",
                self.manager.get_layer('mac').database.get("macExtendedAddress")
            )

        self.database.set("nwkPANId", selected_pan_id)

        # Build ZigBee beacon payload
        beacon_payload = ZigBeeBeacon(
            proto_id = 0,
            stack_profile = self.database.get("nwkStackProfile"),
            nwkc_protocol_version = self.database.get("nwkcProtocolVersion"),
            router_capacity = 1, #((self.database.get("nwkCapabilityInformation") >> 1) & 1),
            end_device_capacity = 1,
            device_depth = 0 if network_address == 0 else 1,
            extended_pan_id = self.database.get("nwkExtendedPANID"),
            tx_offset = 0xFFFFFF, # non beacon network, default value
            update_id = self.database.get("nwkUpdateId")
        )
        self.manager.get_layer('mac').database.set("macBeaconPayload", bytes(beacon_payload))
        start = self.manager.get_layer('mac').get_service('management').start(
            selected_pan_id,
            pan_coordinator=True,
            beacon_order=beacon_order,
            superframe_order=superframe_order,
            battery_life_extension=battery_life_extension,
            coord_realignement=False # for now, should be different if we update an existing PAN
        )

        last_beacon = self.manager.get_layer('mac').database.get("macLastBeacon")
        channel = self.manager.get_layer('phy').get_channel()
        channel_page = self.manager.get_layer('phy').get_channel_page()
        beacon_payload.pan_descriptor = Dot15d4PANNetwork(last_beacon, channel_page, channel)
        self.database.set(
            "nwkOwnNetwork",
            ZigbeeNetwork(
                beacon_payload
            )
        )
        return start

    @Dot15d4Service.request("NLME-SYNC")
    def sync(self,track=False):
        """
        Implements the NLME-SYNC request.

        Allows to synchronize on the coordinator or router of a network.
        """
        macRxOnWhenIdle = self.manager.get_layer('mac').database.get("macRxOnWhenIdle")
        if not track:
            # If non enabled beacon network ...
            if macRxOnWhenIdle:
                # Get parent address (or terminate if not found)
                table = self.database.get("nwkNeighborTable")
                parent = table.get_parent()
                if parent is None:
                    return False

                # Perform a poll operation
                return self.manager.get_layer('mac').get_service('management').poll(
                    coordinator_pan_id=parent.pan_id,
                    coordinator_address=parent.address
                )
            else:
                # Enable auto request
                self.manager.get_layer('mac').database.set("macAutoRequest", True)
                # Perform a synchronization
                return self.manager.get_layer('mac').get_service('management').sync(
                    channel = self.manager.get_layer('phy').get_channel(),
                    channel_page = self.manager.get_layer('phy').get_channel_page(),
                    track_beacon=False
                )
        else:
            if macRxOnWhenIdle:
                return False
            else:
                # Enable auto request
                self.manager.get_layer('mac').database.set("macAutoRequest", True)
                # Perform a synchronization
                return self.manager.get_layer('mac').get_service('management').sync(
                    channel = self.manager.get_layer('phy').get_channel(),
                    channel_page = self.manager.get_layer('phy').get_channel_page(),
                    track_beacon=True
                )

    def on_beacon_npdu(self, pan_descriptor, beacon_payload):
        """
        Callback processing Beacon NPDU forwarded from NWK manager.
        """
        beacon_payload.pan_descriptor = pan_descriptor
        self.add_packet_to_queue(beacon_payload)


    def on_command_npdu(self, npdu, link_quality):
        """
        Callback processing Commands NPDU forwarded from NWK manager.
        """
        # Check if security header is present
        security_use = ZigbeeSecurityHeader in npdu and npdu[ZigbeeSecurityHeader].underlayer.__class__ is ZigbeeNWK
        if security_use:
            nsdu = ZigbeeNWKCommandPayload(npdu.data)
        else:
            nsdu = npdu[ZigbeeNWKCommandPayload]

        if nsdu.cmd_identifier == 6:
            self.on_rejoin_command(nsdu, npdu.source, npdu.ext_src)
        # Add packet to FIFO
        self.add_packet_to_queue(nsdu)

    def on_rejoin_command(self, nsdu, source_address, extended_source_address):
        """
        Callback processing Rejoin Commands NSDU.
        """

        table = self.database.get("nwkNeighborTable")
        candidate = table.select_by_extended_address(extended_source_address)

        capability_information = (
            int(nsdu.alternate_pan_coordinator) |
            (int(nsdu.device_type) << 1) |
            (int(nsdu.power_source) << 2) |
            (int(nsdu.receiver_on_when_idle) << 3) |
            (0 << 4) |
            (int(nsdu.security_capability) << 5) |
            (int(nsdu.allocate_address) << 7)
        )

        if candidate is None:
            network_address = source_address
        else:
            network_address = candidate.address

        permit_join = self.manager.get_layer("mac").database.get("macAssociationPermit")

        sequence_number = self.database.get("nwkSequenceNumber")
        self.database.set("nwkSequenceNumber", sequence_number+1)
        radius = self.database.get("nwkMaxDepth") * 2

        if permit_join:
            routers = table.select_routers_by_pan_id(self.database.get("nwkPANId"))

            table.update(
                network_address,
                device_type=(
                                ZigbeeDeviceType.ROUTER if
                                int(nsdu.device_type) == 1 else
                                ZigbeeDeviceType.END_DEVICE
                ),
                transmit_failure=0,
                lqi=0,
                outgoing_cost=0,
                age=0,
                extended_pan_id=self.database.get("nwkExtendedPANID"),
                logical_channel=self.manager.get_layer("phy").get_channel(),
                depth=len(routers) + 1,
                potential_parent=False,
                update_id=self.database.get("nwkUpdateId"),
                pan_id=self.database.get("nwkPANId"),
                extended_address=extended_source_address,
                rx_on_when_idle=bool((capability_information >> 3) & 1),
            )

            nwkAddressMap = self.database.get("nwkAddressMap")
            nwkAddressMap[extended_source_address] = network_address
            self.database.set("nwkAddressMap", nwkAddressMap)


            # Build rejoin response
            npdu = ZigbeeNWK(
                frametype=1,
                discover_route=0,
                seqnum=sequence_number,
                radius=radius,
                flags=["extended_src"], #, "extended_dst"],
                destination=network_address,
                source=self.database.get("nwkNetworkAddress"),
                #ext_dst=selected_parent.extended_address, # ?
                ext_src=self.database.get("nwkIeeeAddress")
            )
            nsdu = ZigbeeNWKCommandPayload(
                cmd_identifier=7,
                network_address=network_address,
                rejoin_status=0
            )


            if self.database.get("nwkSecurityLevel") != 0:
                npdu.flags.security = True
                selected_key_material = None

                security_material_set = self.database.get("nwkSecurityMaterialSet")
                for key_material in security_material_set:
                    if key_material.key_sequence_number == self.database.get("nwkActiveKeySeqNumber"):
                        selected_key_material = key_material
                        break

                if selected_key_material is None:
                    return False

                msdu = npdu / ZigbeeSecurityHeader(
                    nwk_seclevel = self.database.get("nwkSecurityLevel"),
                    source = self.database.get("nwkIeeeAddress"),
                    key_type=1,
                    key_seqnum=self.database.get("nwkActiveKeySeqNumber"),
                    fc=selected_key_material.outgoing_frame_counter,
                    data=bytes(nsdu)
                )
                crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
                msdu = crypto_manager.encrypt(msdu)
                selected_key_material.outgoing_frame_counter += 1
            else:
                msdu = npdu / nsdu

            self.manager.get_layer('mac').get_service("data").data(
                msdu,
                destination_address_mode=MACAddressMode.SHORT,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=self.database.get("nwkPANId"),
                destination_address=network_address,
                wait_for_ack=True
            )

            self.indicate_join(
                network_address,
                extended_source_address,
                capability_information,
                rejoin=True,
                secure_rejoin=False
            )
        else:


            # Build rejoin request
            npdu = ZigbeeNWK(
                frametype=1,
                discover_route=0,
                seqnum=sequence_number,
                radius=radius,
                flags=["extended_src"], #, "extended_dst"],
                destination=network_address,
                source=self.database.get("nwkNetworkAddress"),
                #ext_dst=selected_parent.extended_address, # ?
                ext_src=self.database.get("nwkIeeeAddress")
            )
            nsdu = ZigbeeNWKCommandPayload(
                cmd_identifier=7,
                network_address=network_address,
                rejoin_status=1
            )


            if self.database.get("nwkSecurityLevel") != 0:
                npdu.flags.security = True
                selected_key_material = None

                security_material_set = self.database.get("nwkSecurityMaterialSet")
                for key_material in security_material_set:
                    if key_material.key_sequence_number == self.database.get("nwkActiveKeySeqNumber"):
                        selected_key_material = key_material
                        break

                if selected_key_material is None:
                    return False

                msdu = npdu / ZigbeeSecurityHeader(
                    nwk_seclevel = self.database.get("nwkSecurityLevel"),
                    source = self.database.get("nwkIeeeAddress"),
                    key_type=1,
                    key_seqnum=self.database.get("nwkActiveKeySeqNumber"),
                    fc=selected_key_material.outgoing_frame_counter,
                    data=bytes(nsdu)
                )
                crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
                msdu = crypto_manager.encrypt(msdu)
                selected_key_material.outgoing_frame_counter += 1
            else:
                msdu = npdu / nsdu

            self.manager.get_layer('mac').get_service("data").data(
                msdu,
                destination_address_mode=MACAddressMode.SHORT,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=self.database.get("nwkPANId"),
                destination_address=network_address,
                wait_for_ack=True
            )

class NWKInterpanService(NWKService):
    """
    NWK pseudo-service forwarding InterPAN packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_interpan")

    @Dot15d4Service.request("INTRP-DATA")
    def interpan_data(
                        self,
                        asdu,
                        asdu_handle=0,
                        source_address_mode=MACAddressMode.EXTENDED,
                        destination_address_mode=MACAddressMode.SHORT,
                        destination_pan_id=0xFFFF,
                        destination_address=0xFFFF,
                        profile_id=0,
                        cluster_id=0,
                        acknowledged_transmission=False
    ):
        """
        Implements INTRP-DATA Request.

        Transmits InterPAN PDU.
        """
        # Infer delivery mode from destination address
        if destination_address == 0xFFFF:
            delivery_mode = 2
        else:
            delivery_mode = 0

        # Build scapy packet for InterPAN PDU
        data = ZigbeeNWKStub()/ZigbeeAppDataPayloadStub(
            cluster=cluster_id,
            profile=profile_id,
            delivery_mode=delivery_mode,
            data=asdu
        )

        self.manager.get_layer('mac').get_service("data").data(
            data,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            destination_address_mode=destination_address_mode,
            wait_for_ack=acknowledged_transmission
        )

    def on_interpan_npdu(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        """
        Callback processing InterPAN NPDU forwarded by NWK manager.
        """

        # Populate profile ID & Cluster
        profile_id = pdu.profile
        cluster_id = pdu.cluster

        # Encapsulate PDU according to the selected profile (needed for correct scapy encapsulation)
        if NewZigbeeAppDataPayloadStub in pdu:
            asdu = bytes(pdu[NewZigbeeAppDataPayloadStub].payload)
        elif ZigbeeAppDataPayloadStub in pdu:
            asdu = pdu[ZigbeeAppDataPayloadStub].data

        if profile_id == 0xc05e and cluster_id == 0x1000:
            asdu = ZigbeeZLLCommissioningCluster(asdu)

        # Let's trigger an InterPAN indication
        self.indicate_interpan_data(
                                    asdu,
                                    profile_id=profile_id,
                                    cluster_id=cluster_id,
                                    destination_pan_id=destination_pan_id,
                                    destination_address=destination_address,
                                    source_pan_id=source_pan_id,
                                    source_address=source_address,
                                    link_quality=link_quality
        )

    @Dot15d4Service.indication("INTRP-DATA")
    def indicate_interpan_data(
                                self,
                                asdu,
                                profile_id=0,
                                cluster_id=0,
                                destination_pan_id=0xFFFF,
                                destination_address=0xFFFF,
                                source_pan_id=0xFFFF,
                                source_address=0xFFFF,
                                link_quality=255
    ):
        """
        Implements INTRP-DATA indication.
        """
        return (asdu,
            {
            "profile_id":profile_id,
            "cluster_id":cluster_id,
            "destination_pan_id":destination_pan_id,
            "destination_address":destination_address,
            "source_pan_id":source_pan_id,
            "source_address":source_address,
            "link_quality":link_quality
        })


@state(NWKIB)
@alias('nwk')
class NWKManager(Dot15d4Manager):
    """
    This class implements the Zigbee Network manager (NWK) and the Inter-PAN APS.
    It handles network-level operations, such as discovery, association or network initiation.

    It exposes two services providing the appropriate API.
    """
    def init(self):
        self.add_service("data", NWKDataService(self))
        self.add_service("management", NWKManagementService(self))
        self.add_service("interpan", NWKInterpanService(self))
        self.__pending_join_indication = None

    def add_key(self, key, key_sequence_number=None, outgoing_frame_counter=0):
        """
        This method adds an encryption key for Network-level Security.
        """
        networkSecurityMaterialSet = self.database.get("nwkSecurityMaterialSet")
        securityMaterial = NetworkSecurityMaterial(
            key,
            key_sequence_number=key_sequence_number,
            outgoing_frame_counter=outgoing_frame_counter
        )
        if securityMaterial not in networkSecurityMaterialSet:
            networkSecurityMaterialSet.append(securityMaterial)
        logger.info("[nwk] new security material added: {}".format(str(securityMaterial)))
        self.database.set("nwkSecurityMaterialSet", networkSecurityMaterialSet)


    def decrypt(self, pdu):
        """
        This method decrypts a PDU if the corresponding security material is found in the database.
        """
        # Check if Security Header is present in PDU
        if ZigbeeSecurityHeader not in pdu:
            logger.info("[nwk] decryption failure - missing security header.")
            return pdu, False

        # Check the current security level
        securityLevel = self.database.get("nwkSecurityLevel")

        if securityLevel == 0:
            logger.info("[nwk] decryption failure - attempt to decrypt a pdu with nwkSecurityLevel set to 0.")
            return pdu, False

        # Check if mandatory fields are present in PDU
        if (
                not hasattr(pdu[ZigbeeSecurityHeader], "fc") or
                not hasattr(pdu[ZigbeeSecurityHeader], "source") or
                not hasattr(pdu[ZigbeeSecurityHeader], "key_seqnum")
        ):
            logger.info("[nwk] decryption failure - missing mandatory data in security header.")
            return pdu, False

        received_frame_count = pdu[ZigbeeSecurityHeader].fc
        key_sequence_number = pdu[ZigbeeSecurityHeader].key_seqnum
        sender_address = pdu[ZigbeeSecurityHeader].source

        # Select the  key from the database
        security_material_set = self.database.get("nwkSecurityMaterialSet")

        selected_key_material = None
        for key_material in security_material_set:
            if key_material.key_sequence_number == key_sequence_number:
                selected_key_material = key_material
                break
        if selected_key_material is None:
            logger.info("[nwk] decryption failure - no matching key found.")
            return pdu, False

        # Check frame counter
        if (
            sender_address in selected_key_material.incoming_frame_counters and
            received_frame_count < selected_key_material.incoming_frame_counters[sender_address] and
            self.database.get("nwkAllFresh")
        ):
            logger.info("[nwk] decryption failure - bad frame counter.")
            return pdu, False

        # Instantiate the Crypto Manager
        network_crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
        # Try to decrypt PDU
        cleartext, status = network_crypto_manager.decrypt(pdu)
        if status:
            # Increase incoming frame counter
            selected_key_material.add_incoming_frame_counter(sender_address, received_frame_count+1)
            return cleartext, True
        else:
            print("Undecoded:", bytes(pdu).hex())
            logger.info("[nwk] decryption failure - MIC not matching.")
            return pdu, False

    @source('mac', 'MCPS-DATA')
    def on_mcps_data(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        """
        Callback processing MAC MCPS Data indication.
        """
        # If we have an InterPAN PDU, forwards it to the NWK InterPAN service
        if ZigbeeNWKStub in pdu and (ZigbeeAppDataPayloadStub in pdu or NewZigbeeAppDataPayloadStub in pdu):
            self.get_service("interpan").on_interpan_npdu(
                pdu,
                destination_pan_id,
                destination_address,
                source_pan_id,
                source_address,
                link_quality
            )
        # If we have a regular NWK PDU:
        elif ZigbeeNWK in pdu:
            # If PDU unencrypted, check if we allow it in current configuration
            if ZigbeeSecurityHeader not in pdu and self.database.get("nwkSecureAllFrames"):
                logger.info("[nwk] nwkSecureAllFrames attribute indicates that we only accept security enabled frames.")
                return

            # If PDU encrypted, let's try to decrypt it
            if ZigbeeSecurityHeader in pdu and pdu[ZigbeeSecurityHeader].underlayer.__class__ is ZigbeeNWK:
                decrypted, success = self.decrypt(pdu)
                if success:
                    pdu = decrypted
                else:
                    return


            # Once decrypted, forward to the right service depending on the frame type
            if pdu.frametype == 0:
                # Data PDU, forward to NWK Data Service
                self.get_service("data").on_data_npdu(pdu, link_quality)
            elif pdu.frametype == 1:
                # Management PDU, forward to NWK Management Service
                self.get_service("management").on_command_npdu(pdu, link_quality)
            else:
                # InterPAN PDU, forward to NWK InterPAN Service
                self.get_service("interpan").on_interpan_npdu(
                    pdu,
                    destination_pan_id,
                    destination_address,
                    source_pan_id,
                    source_address,
                    link_quality
                )

    @source('mac', 'MLME-ASSOCIATE')
    def on_mlme_associate(
                            self,
                            source_address,
                            capability_information,
                            security_level,
                            key_id_mode,
                            key_source,
                            key_index,
                            channel_offset,
                            hopping_sequence_id,
                            dsme_association,
                            direction,
                            allocation_order,
                            hopping_sequence_request
    ):
        """
        Callback processing MAC Association indication.
        """
        # Check if another device exists with the same address
        table = self.database.get("nwkNeighborTable")
        node = table.select_by_extended_address(source_address)
        router = (((capability_information >> 1) & 1) == 0)
        if node is not None:
            if not router:
                device_type = ZigbeeDeviceType.END_DEVICE
            else:
                device_type = ZigbeeDeviceType.ROUTER

            if device_type == node.device_type:
                success = self.get_layer('mac').get_service("management").associate_response(
                    source_address,
                    node.address,
                    association_status=MACAssociationStatus.ASSOCIATION_SUCCESSFUL
                )
                if success:
                    self.__pending_join_indication = (
                        new_address,
                        source_address,
                        capability_information,
                        False,
                        False
                    )
                return success
            else:
                table.delete(node.address)

        new_address = self._address_assignment(
            depth=0, # we only consider a depth of 0 (coordinator) for now
            router_node=router
        )

        if new_address is None:
            self.get_layer('mac').get_service("management").associate_response(
                source_address,
                0,
                association_status=MACAssociationStatus.PAN_AT_CAPACITY
            )
        else:
            routers = table.select_routers_by_pan_id(self.database.get("nwkPANId"))

            table.update(
                new_address,
                device_type=(
                                ZigbeeDeviceType.ROUTER if
                                router else
                                ZigbeeDeviceType.END_DEVICE
                ),
                transmit_failure=0,
                lqi=0,
                outgoing_cost=0,
                age=0,
                extended_pan_id=self.database.get("nwkExtendedPANID"),
                logical_channel=self.get_layer("phy").get_channel(),
                depth=len(routers) + 1,
                potential_parent=False,
                update_id=self.database.get("nwkUpdateId"),
                pan_id=self.database.get("nwkPANId"),
                extended_address=source_address,
                rx_on_when_idle=bool((capability_information >> 3) & 1),
            )

            nwkAddressMap = self.database.get("nwkAddressMap")
            nwkAddressMap[source_address] = new_address
            self.database.set("nwkAddressMap", nwkAddressMap)

            success = self.get_layer('mac').get_service("management").associate_response(
                source_address,
                new_address,
                association_status=MACAssociationStatus.ASSOCIATION_SUCCESSFUL
            )

            if success:
                self.__pending_join_indication = (
                    new_address,
                    source_address,
                    capability_information,
                    False,
                    False
                )

            return success

    def _address_assignment(self, depth=0, router_node=False):

        table = self.database.get("nwkNeighborTable")
        pan_id = self.database.get("nwkPANId")

        routers = table.select_routers_by_pan_id(pan_id)
        end_devices = table.select_end_devices_by_pan_id(pan_id)
        assigned_addresses = [r.address for r in routers] + [e.address for e in end_devices]

        parent = table.get_parent()
        if parent is None:
            parent_address = self.database.get("nwkNetworkAddress")
        else:
            parent_address = parent.address

        if self.database.get("nwkAddrAlloc") == 2:
            # Stochastic address assignment
            new_address = randint(1, 0xFFFD)
            while new_address in assigned_addresses:
                new_address = randint(1, 0xFFFD)
            return new_address

        elif self.database.get("nwkAddrAlloc") == 0:
            # Distributed address assignment
            cm = self.database.get("nwkMaxChildren")
            lm = self.database.get("nwkMaxDepth")
            rm = self.database.get("nwkMaxRouters")
            cskip = (
                (1 + cm * (lm - depth - 1))
                if rm == 1 else
                (1 + cm - rm  - cm * (rm ** (lm - depth - 1)))
            )

            if cskip == 0:
                return None
            else:
                if router_node:
                    new_address = parent_address + 1 + len(routers) * cskip
                else:
                    new_address = parent_address + cskip * rm + (len(end_devices)) # + 1 or not ?
            return new_address

    @source('mac', 'MLME−DATA-REQ')
    def on_mlme_data_req(self, pdu):
        if self.__pending_join_indication is not None:
            self.get_service("management").indicate_join(
                *self.__pending_join_indication
            )
            self.__pending_join_indication = None

    @source('mac', 'MLME-BEACON-NOTIFY')
    def on_mlme_beacon_notify(self, beacon_payload, pan_descriptor):
        """
        Callback processing MAC Beacon Notify indication.
        """
        # If we got bytes here, encapsulate into scapy ZigBeeBeacon
        beacon_payload = bytes(beacon_payload)

        if isinstance(beacon_payload, bytes):
            beacon_payload = ZigBeeBeacon(beacon_payload)
            # Check if this is a Zigbee beacon

        if hasattr(beacon_payload, "proto_id") and beacon_payload.proto_id in (0, 75, 92): #TODO: proto id filter at 0 does not match esp32c6 implem ? check
            # Forward it to NWK management service
            self.get_service("management").on_beacon_npdu(pan_descriptor, beacon_payload)

            # Update the neighbor table
            table = self.database.get("nwkNeighborTable")

            table.update(
                pan_descriptor.coord_addr,
                device_type=(
                                ZigbeeDeviceType.COORDINATOR if
                                pan_descriptor.coord_addr == 0 else
                                ZigbeeDeviceType.ROUTER
                ),
                transmit_failure=0,
                lqi=pan_descriptor.link_quality,
                outgoing_cost=0,
                age=0,
                extended_pan_id=beacon_payload.extended_pan_id,
                logical_channel=pan_descriptor.channel,
                depth=beacon_payload.device_depth,
                beacon_order=pan_descriptor.beacon_order,
                permit_joining=pan_descriptor.assoc_permit,
                potential_parent=True,
                update_id=beacon_payload.update_id,
                pan_id=pan_descriptor.coord_pan_id
            )

NWKManager.add(APSManager)
