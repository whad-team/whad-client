from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.constants import MACAddressMode, MACScanType, \
    MACDeviceType, MACPowerSource, MACConstants
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
                    wait_for_ack=True,
                    pan_id_compress=True
                )
                duration = (
                            self.manager.get_layer('mac').database.get("macResponseWaitTime") *
                            MACConstants.A_BASE_SUPERFRAME_DURATION *
                            self.manager.get_layer('phy').symbol_duration
                )
                self.manager.get_layer('mac').database.set("macPanId", selected_parent.pan_id)

                self.manager.get_layer('mac').get_service('management').poll(
                    coordinator_pan_id=selected_parent.pan_id,
                    coordinator_address=selected_parent.address,
                    pan_id_compress=True
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

        # Add packet to FIFO
        self.add_packet_to_queue(nsdu)

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
