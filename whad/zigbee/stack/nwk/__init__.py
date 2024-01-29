from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.zigbee.stack.nwk.exceptions import NWKTimeoutException, NWKInvalidKey
from whad.zigbee.stack.nwk.database import NWKIB
from whad.zigbee.stack.nwk.security import NetworkSecurityMaterial
from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType
from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.common.stack import Layer, alias, source, state

from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWKStub, ZigbeeNWK, \
    ZigbeeSecurityHeader, ZigbeeNWKCommandPayload, ZigbeeAppDataPayload, \
    ZigbeeAppDataPayloadStub, LinkStatusEntry
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, NewZigbeeAppDataPayloadStub

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

class NWKManagementService(NWKService):
    """
    NWK service processing Management packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_management")

class NWKInterpanService(NWKService):
    """
    NWK pseudo-service forwarding InterPAN packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_interpan")


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
            self.get_service("interpan").on_interpan_npdu(pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality)

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
                self.get_service("interpan").on_interpan_npdu(pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality)

    @source('mac', 'MLME-BEACON-NOTIFY')
    def on_mlme_beacon_notify(self, beacon_payload, pan_descriptor):
        """
        Callback processing MAC Beacon Notify indication.
        """
        # If we got bytes here, encapsulate into scapy ZigBeeBeacon
        if isinstance(beacon_payload, bytes):
            beacon_payload = ZigBeeBeacon(beacon_payload)

        # Check if this is a Zigbee beacon
        if hasattr(beacon_payload, "proto_id") and beacon_payload.proto_id == 0:
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
