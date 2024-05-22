from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.address import Dot15d4Address
from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.rf4ce.stack.nwk.exceptions import NWKTimeoutException
from whad.rf4ce.stack.nwk.database import NWKIB
from whad.rf4ce.stack.nwk.pairing import PairingEntry
from whad.rf4ce.crypto import generate_random_value, xor, RF4CECryptoManager, RF4CEKeyDerivation
from whad.scapy.layers.rf4ce import RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Request, \
    RF4CE_Hdr, RF4CE_Cmd_Key_Seed, RF4CE_Cmd_Pair_Request, RF4CE_Cmd_Pair_Response, \
    RF4CE_Cmd_Discovery_Response, RF4CE_Cmd_Ping_Request, RF4CE_Cmd_Ping_Response, \
    RF4CE_Data_Hdr, RF4CE_Vendor_Hdr, RF4CE_Vendor_MSO_Get_Attribute_Response, \
    RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Check_Validation_Response
from whad.common.stack import Layer, alias, source, state
from whad.rf4ce.stack.apl import APLManager

from random import randint
from time import time, sleep
from struct import pack

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
    NWK service forwarding data packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_data")



    @Dot15d4Service.request("NLDE-DATA")
    def data(self, nsdu, pairing_reference=None, profile_id=0, vendor_id=0x0000, tx_options=0):
        """
        Request transmitting NSDU according to the provided parameters.
        """
        broadcast = bool(tx_options & 1)
        ieee_dest_mode = bool((tx_options & (1 << 1)) >> 1)
        ack_mode = bool((tx_options & (1 << 2)) >> 2)
        security_mode = bool((tx_options & (1 << 3)) >> 3)
        channel_agility = bool((tx_options & (1 << 4)) >> 4)
        channel_normalization = bool((tx_options & (1 << 5)) >> 5)
        vendor_mode = bool((tx_options & (1 << 6)) >> 6)


        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)

        if frame_counter == 0xffffffff:
            # frame counter expired, terminate without further processing
            return False

        if vendor_mode:

            npdu = (
                RF4CE_Hdr(
                    security_enabled = security_mode,
                    frame_counter = frame_counter,
                    reserved = 1,
                    protocol_version = 1
                ) /
                RF4CE_Vendor_Hdr(
                    profile_id = profile_id,
                    vendor_id = vendor_id
                ) /
                nsdu
            )
        else:
            npdu = (
                RF4CE_Hdr(
                    security_enabled = security_mode,
                    frame_counter = frame_counter,
                    reserved = 1,
                    protocol_version = 1
                ) /
                RF4CE_Data_Hdr(
                    profile_id = profile_id,
                    vendor_id = vendor_id
                ) /
                nsdu
            )


        pairing_table = self.database.get('nwkPairingTable')
        try:
            if pairing_reference is not None:
                pairing_entry = pairing_table[pairing_reference]
            else:
                pairing_entry = None
        except IndexError:
            pairing_entry = None

        if broadcast:
            destination_pan_id = 0xFFFF
            destination_address = 0xFFFF

        else:
            if pairing_entry is not None:
                destination_pan_id = pairing_entry.destination_pan_id
                destination_address = pairing_entry.destination_ieee_address if ieee_dest_mode else pairing_entry.destination_network_address
                source_address = pairing_entry.source_network_address
            else:
                # no entry
                return False

        if pairing_entry is not None:
            channel = pairing_entry.channel
        else:
            channel = self.manager.get_layer('phy').get_channel()

        if security_mode:
            if pairing_entry is not None and pairing_entry.link_key is not None:
                link_key = pairing_entry.link_key

                enc_npdu = RF4CECryptoManager(
                    key = pairing_entry.link_key
                ).encrypt(
                    npdu,
                    source=pack('<Q', self.manager.get_layer('mac').database.get('macExtendedAddress')),
                    destination=pack('<Q', pairing_entry.destination_ieee_address),
                    rf4ce_only=True
                )
                npdu = enc_npdu

            else:
                return False

        if ack_mode:
            ack = self.manager.get_layer('mac').get_service("data").data(
                npdu,
                destination_address_mode=MACAddressMode.EXTENDED if ieee_dest_mode else MACAddressMode.SHORT,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=destination_pan_id,
                destination_address=destination_address,
                pan_id_suppressed = False,
                wait_for_ack=True
            )
            return ack
        else:
            self.manager.get_layer('mac').get_service("data").data(
                npdu,
                destination_address_mode=MACAddressMode.EXTENDED if ieee_dest_mode else MACAddressMode.SHORT,
                source_address_mode=MACAddressMode.SHORT,
                destination_pan_id=destination_pan_id,
                destination_address=destination_address,
                pan_id_suppressed = False,
                wait_for_ack=False
            )
            return True

    def on_data_npdu(self, npdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality=255):
        """
        Callback processing NPDU from NWK manager.

        It forwards the NPDU to indicate_data method.
        """
        self.indicate_data(npdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality)

    @Dot15d4Service.indication("NLDE-DATA")
    def indicate_data(self, npdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality=255):
        """
        Indication transmitting NSDU to upper layer.
        """
        #npdu.show()
        if RF4CE_Data_Hdr in npdu:
            nsdu = npdu[RF4CE_Data_Hdr][1:]
        elif RF4CE_Vendor_Hdr in npdu:
            nsdu = npdu[RF4CE_Vendor_Hdr][1:]
        else:
            nsdu = npdu

        rx_flags = (
            int(destination_address == 0xffff) |
            (int(npdu.security_enabled) << 1) |
            (int(npdu.frame_type == 3) << 2)
        )

        return (
            npdu,
            {
                "pairing_reference" : npdu.pairing_entry_index,
                "profile_id" : npdu.profile_id,
                "vendor_id" : npdu.vendor_id if hasattr(npdu, "vendor_id") else None,
                "link_quality" : link_quality,
                "rx_flags" : rx_flags
            }
        )



class NWKManagementService(NWKService):
    """
    NWK service forwarding management packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_management")

    @Dot15d4Service.request("NLME-PAIR")
    def pair_request(self, destination_pan_id, destination_ieee_address, list_of_device_types=[1], list_of_profiles=[192], key_exchange_transfer_count=3):
        """
        Request allowing the NWK layer to transmit a pairing request.
        """
        node_capability =  self.database.get("nwkcNodeCapabilities")
        channel_normalization_capable = (node_capability >> 3) & 1
        security_capable = (node_capability >> 2) & 1
        power_source = "battery_source" if ((node_capability >> 1) & 1) == 0 else "alternating_current_source"
        node_type = "controller" if (node_capability & 1) == 0 else "target"

        pairing_reference = None
        # Get entry
        pairing_entry = None
        pairing_table = self.database.get("nwkPairingTable")
        for pairing_reference in range(len(pairing_table)):
            if (
                pairing_table[pairing_reference].destination_ieee_address == destination_ieee_address and
                pairing_table[pairing_reference].destination_pan_id == destination_pan_id
            ):
                pairing_entry = pairing_table[pairing_reference]
                break

        if pairing_entry is None:
            # Create a new Pairing Entry here
            pairing_entry = PairingEntry(
                source_network_address = self.manager.get_layer('mac').database.get("macShortAddress"),
                channel = self.manager.get_layer('phy').get_channel(),
                destination_ieee_address = destination_ieee_address,
                destination_pan_id = destination_pan_id,
                destination_network_address = None, # unknown at this point
                capabilities = node_capability,
                frame_counter = 0,
                link_key = key_exchange_transfer_count # unknown for now, use it to transfer key_exchange_transfer_count
            )
            pairing_table.append(pairing_entry)
            pairing_reference = len(pairing_table) - 1

        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)


        # Build a discovery request
        discovery_request = (
            RF4CE_Hdr(
                protocol_version=1,
                security_enabled=0,
                frame_counter=frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Discovery_Request(
                channel_normalization_capable = channel_normalization_capable,
                security_capable = security_capable,
                power_source = power_source,
                node_type = node_type,
                vendor_identifier = self.database.get("nwkVendorIdentifier"),
                vendor_string = self.database.get("nwkVendorString"),
                number_of_supported_profiles = len(list_of_profiles),
                profile_identifier_list = list_of_profiles,
                number_of_supported_device_types = len(list_of_device_types),
                device_type_list = list_of_device_types,
                user_string_specificied = int(self.database.get("nwkUserString") is not None),
                user_string = self.database.get("nwkUserString"),
                requested_device_type = 0xFF
            )
        )

        for _ in range(2):
            discovery_request.frame_counter = frame_counter
            #self.manager.get_layer('phy').set_channel(channel)
            ack = self.manager.get_layer('mac').get_service("data").data(
                discovery_request,
                destination_address_mode=MACAddressMode.SHORT,
                source_address_mode=MACAddressMode.EXTENDED,
                destination_pan_id=0xFFFF,
                destination_address=0xFFFF,
                pan_id_suppressed = False,
                wait_for_ack=True
            )
            frame_counter = self.database.get("nwkFrameCounter")
            self.database.set("nwkFrameCounter", frame_counter + 1)


        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)

        #  Build the pairing response
        pairing_request = (
            RF4CE_Hdr(
                reserved = 1,
                protocol_version = 1,
                security_enabled = 0,
                frame_counter = frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Pair_Request
            (
                nwk_addr = 0xFFFE,# self.manager.get_layer('mac').database.get('macShortAddress'),
                channel_normalization_capable = channel_normalization_capable,
                security_capable = security_capable,
                power_source = power_source,
                node_type = node_type,
                vendor_identifier = self.database.get("nwkVendorIdentifier"),
                vendor_string = self.database.get("nwkVendorString"),
                number_of_supported_profiles = len(list_of_profiles),
                profile_identifier_list = list_of_profiles,
                number_of_supported_device_types = len(list_of_device_types),
                device_type_list = list_of_device_types,
                user_string_specificied = int(self.database.get("nwkUserString") is not None),
                user_string = self.database.get("nwkUserString"),
                key_exchange_transfer_count = key_exchange_transfer_count
            )
        )

        ack = self.manager.get_layer('mac').get_service("data").data(
            pairing_request,
            destination_address_mode=MACAddressMode.EXTENDED,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_pan_id=destination_pan_id,
            destination_address=destination_ieee_address,
            pan_id_suppressed = False,
            wait_for_ack=True
        )

        if not ack:
            return None

        pair_response = None
        start = time()
        while (time() - start) < 3 and pair_response is None:
            try:
                pair_response = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Pair_Response in pkt, timeout=0.01)
            except NWKTimeoutException:
                pass

        if pair_response is None:
            return None

        self.manager.get_layer('mac').set_short_address(pair_response.allocated_nwk_addr)
        self.manager.get_layer('mac').database.set("macPanId", destination_pan_id)
        pair_response.show()

        key_seeds = []
        while len(key_seeds) != key_exchange_transfer_count+1:
            key_seed = None
            start = time()
            while (time() - start) < 3 and key_seed is None:
                try:
                    key_seed = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Key_Seed in pkt, timeout=0.01)
                    key_seeds.append(key_seed.seed_data)

                except NWKTimeoutException:
                    pass

        derivation = RF4CEKeyDerivation(seeds = key_seeds, seeds_number = key_exchange_transfer_count)
        key = derivation.key

        pairing_entry.link_key = key
        pairing_entry.destination_network_address = pair_response.nwk_addr
        pairing_entry.mark_as_active()

        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)
        unenc_ping_req = (
            RF4CE_Hdr(
                protocol_version = 1,
                security_enabled = 1, # !!
                frame_counter = frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Ping_Request
            (
                ping_options = 0,
                ping_payload = generate_random_value(32)
            )
        )

        source_ieee_address = self.manager.get_layer('mac').database.get("macExtendedAddress")

        source_address_formatted = pack('<Q', pairing_entry.destination_ieee_address)
        destination_address_formatted = pack('<Q', source_ieee_address)


        enc_ping_req = RF4CECryptoManager(
            key = key
        ).encrypt(
            unenc_ping_req,
            destination=source_address_formatted,
            source=destination_address_formatted,
            rf4ce_only=True
        )

        ack = self.manager.get_layer('mac').get_service("data").data(
            enc_ping_req, #enc_ping_resp, #unenc_ping_resp,
            destination_address_mode=MACAddressMode.EXTENDED,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_pan_id=0xFFFF,
            destination_address=destination_ieee_address,
            pan_id_suppressed = False,
            wait_for_ack=True
        )

        ping_resp = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Ping_Response in pkt, timeout=3)
        ping_resp.show()
        return pairing_reference

    @Dot15d4Service.response("NLME-PAIR")
    def pair_response(self, destination_address, accept=True, list_of_device_types=[9], list_of_profiles=[192], pairing_reference=None):
        """
        Reponse allowing to the NWK layer to transmit a pairing response.
        """
        node_capability =  self.database.get("nwkcNodeCapabilities")
        channel_normalization_capable = (node_capability >> 3) & 1
        security_capable = (node_capability >> 2) & 1
        power_source = "battery_source" if ((node_capability >> 1) & 1) == 0 else "alternating_current_source"
        node_type = "controller" if (node_capability & 1) == 0 else "target"

        # Get entry
        pairing_entry = None
        try:
            pairing_table = self.database.get("nwkPairingTable")
            pairing_entry = pairing_table[pairing_reference]

        except (IndexError, TypeError):
            # something went wrong, terminate
            return False

        if pairing_entry is None:
            return False


        # Allocate network address
        network_address = None
        if (pairing_entry.capabilities & 1) == 0: #  controller
            already_allocated_addresses = []
            for node in self.database.get("nwkPairingTable"):
                already_allocated_addresses.append(node.source_network_address) # theoretically, it's always our own address
                already_allocated_addresses.append(node.destination_network_address)

            # remove duplicates
            already_allocated_addresses = list(set(already_allocated_addresses))
            while network_address is None or network_address in already_allocated_addresses:
                network_address =  randint(0x0000, 0xFFFD)

        else:
            network_address = 0xFFFE


        # Update network address of the pairing entry
        pairing_entry.destination_network_address = network_address # newly allocated address

        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)

        #  Build the pairing response
        pairing_response = (
            RF4CE_Hdr(
                protocol_version = 1,
                security_enabled = 0,
                frame_counter = frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Pair_Response
            (
                status = (0 if accept else 1),
                allocated_nwk_addr = network_address,
                nwk_addr = self.manager.get_layer('mac').database.get('macShortAddress'),
                channel_normalization_capable = channel_normalization_capable,
                security_capable = security_capable,
                power_source = power_source,
                node_type = node_type,
                vendor_identifier = self.database.get("nwkVendorIdentifier"),
                vendor_string = self.database.get("nwkVendorString"),
                number_of_supported_profiles = len(list_of_profiles),
                profile_identifier_list = list_of_profiles,
                number_of_supported_device_types = len(list_of_device_types),
                device_type_list = list_of_device_types,
                user_string_specificied = int(self.database.get("nwkUserString") is not None),
                user_string = self.database.get("nwkUserString"),


            )
        )
        self.manager.get_layer('mac').database.set("macImplicitBroadcast", True)

        ack = self.manager.get_layer('mac').get_service("data").data(
            pairing_response,
            destination_address_mode=MACAddressMode.EXTENDED,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_pan_id=0xFFFF,
            destination_address=destination_address,
            pan_id_suppressed = False,
            wait_for_ack=True
        )
        if not ack or not accept:
            pairing_table = self.database.get("nwkPairingTable")
            del pairing_table[pairing_reference]
            self.database.set("nwkPairingTable", pairing_table)
            return False
        else:
            if ((pairing_entry.capabilities >> 2) & 1) == 1 and security_capable == 1:

                # security enabled
                # Step 1: generate random 128 bit link key
                link_key = generate_random_value(128)

                # Step 2: generate key seeds
                key_exchange_transfer_count = pairing_entry.link_key

                seeds = [generate_random_value(640) for _ in range(key_exchange_transfer_count)]
                seeds_ph2 = [generate_random_value(128) for _ in range(4)]

                value = link_key
                for seed_ph2 in seeds_ph2:
                    value = xor(seed_ph2, value)

                seeds_ph2.append(value)

                value = b"".join(seeds_ph2)
                for seed in seeds:
                    value = xor(seed, value)

                seeds.append(value)

                for n in range(key_exchange_transfer_count + 1):

                    frame_counter = self.database.get("nwkFrameCounter")
                    self.database.set("nwkFrameCounter", frame_counter + 1)

                    key_seed = (
                        RF4CE_Hdr(
                            protocol_version = 1,
                            security_enabled = 0,
                            frame_counter = frame_counter
                        ) /
                        RF4CE_Command_Hdr() /
                        RF4CE_Cmd_Key_Seed
                        (
                            key_sequence_number = n,
                            seed_data = seeds[n]
                        )
                    )
                    ack = self.manager.get_layer('mac').get_service("data").data(
                        key_seed,
                        destination_address_mode=MACAddressMode.EXTENDED,
                        source_address_mode=MACAddressMode.EXTENDED,
                        destination_pan_id=0xFFFF,
                        destination_address=destination_address,
                        pan_id_suppressed = False,
                        wait_for_ack=True
                    )
                    if not ack:
                        pairing_table = self.database.get("nwkPairingTable")
                        del pairing_table[pairing_reference]
                        self.database.set("nwkPairingTable", pairing_table)
                        return False

                pairing_entry.link_key = link_key
                pairing_entry.mark_as_active()

                ping_req = None
                start = time()
                while (time() - start) < 3 and ping_req is None:
                    try:
                        ping_req = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Ping_Request in pkt, timeout=0.01)
                    except NWKTimeoutException:
                        pass

                if ping_req is None or ping_req.ping_options != 0 or len(ping_req.ping_payload) != 4:
                    pairing_table = self.database.get("nwkPairingTable")
                    del pairing_table[pairing_reference]
                    self.database.set("nwkPairingTable", pairing_table)
                    return False

                frame_counter = self.database.get("nwkFrameCounter")
                self.database.set("nwkFrameCounter", frame_counter + 1)
                unenc_ping_resp = (
                    RF4CE_Hdr(
                        protocol_version = 1,
                        security_enabled = 0, # !!
                        frame_counter = frame_counter
                    ) /
                    RF4CE_Command_Hdr() /
                    RF4CE_Cmd_Ping_Response
                    (
                        ping_options = 0,
                        ping_payload = ping_req.ping_payload
                    )
                )

                ping_resp = (
                    RF4CE_Hdr(
                        protocol_version = 1,
                        security_enabled = 1,
                        frame_counter = frame_counter
                    ) /
                    RF4CE_Command_Hdr() /
                    RF4CE_Cmd_Ping_Response
                    (
                        ping_options = 0,
                        ping_payload = ping_req.ping_payload
                    )
                )
                source_ieee_address = self.manager.get_layer('mac').database.get("macExtendedAddress")

                source_address_formatted = pack('<Q', pairing_entry.destination_ieee_address)
                destination_address_formatted = pack('<Q', source_ieee_address)


                enc_ping_resp = RF4CECryptoManager(
                    key = pairing_entry.link_key
                ).encrypt(
                    ping_resp,
                    destination=source_address_formatted,
                    source=destination_address_formatted,
                    rf4ce_only=True
                )

                ack = self.manager.get_layer('mac').get_service("data").data(
                    unenc_ping_resp, #enc_ping_resp, #unenc_ping_resp,
                    destination_address_mode=MACAddressMode.EXTENDED,
                    source_address_mode=MACAddressMode.EXTENDED,
                    destination_pan_id=0xFFFF,
                    destination_address=destination_address,
                    pan_id_suppressed = False,
                    wait_for_ack=True
                )
                if ack:
                    pairing_entry.mark_as_active()
                return ack

            else:
                # no security
                pairing_entry.mark_as_active()
                return True

    @Dot15d4Service.indication("NLME-PAIR")
    def indicate_pair(self, pdu):
        """
        Indication signaling to the upper layer the reception of a pairing request.
        """
        source_pan_id = pdu.source_pan_id
        destination_pan_id = pdu.destination_pan_id
        source_address = pdu.source_address
        destination_address = pdu.destination_address

        node_capability = (
            (pdu.channel_normalization_capable << 3) |
            (pdu.security_capable << 2) |
            (pdu.power_source << 1) |
            pdu.node_type
        )

        vendor_identifier = pdu.vendor_identifier
        vendor_string = pdu.vendor_string

        application_capability = (
            ((pdu.number_of_supported_profiles & 0x02) << 4) |
            ((pdu.number_of_supported_device_types & 0x02) << 1) |
            pdu.user_string_specificied
        )

        user_string = pdu.user_string
        device_type_list = pdu.device_type_list
        profile_identifier_list = pdu.profile_identifier_list

        key_exchange_transfer_count = pdu.key_exchange_transfer_count

        pairing_entry = None
        for candidate in self.database.get("nwkPairingTable"):
            if (
                source_address == candidate.destination_address and
                destination_address == candidate.source_ieee_address and
                destination_pan_id == candidate.source_pan_id and
                node_capability == candidate.capabilities
            ):
                pairing_entry = candidate
                break

        # Note: maybe move this in a dedicated API ?
        pairing_table = self.database.get("nwkPairingTable")
        if pairing_entry is not None:
            pairing_reference = pairing_table.index(pairing_entry)
            # Do we update something here ? specification is unclear
        else:
            # Create a new Pairing Entry here
            pairing_entry = PairingEntry(
                source_network_address = self.manager.get_layer('mac').database.get("macShortAddress"),
                channel = self.manager.get_layer('phy').get_channel(),
                destination_ieee_address = source_address,
                destination_pan_id = source_pan_id,
                destination_network_address = None, # unknown at this point
                capabilities = node_capability,
                frame_counter = 0,
                link_key = key_exchange_transfer_count # unknown for now, use it to transfer key_exchange_transfer_count
            )
            pairing_table.append(pairing_entry)
            pairing_reference = len(pairing_table) - 1

        return (
            pairing_entry is None,
            {
                "source_pan_id":source_pan_id,
                "source_address":source_address,
                "node_capability":node_capability,
                "vendor_identifier":vendor_identifier,
                "vendor_string":vendor_string,
                "application_capability":application_capability,
                "user_string":user_string,
                "device_type_list":device_type_list,
                "profile_identifier_list":profile_identifier_list,
                "key_exchange_transfer_count":key_exchange_transfer_count,
                "pairing_reference":pairing_reference
            }
        )

    @Dot15d4Service.indication("NLME-DISCOVERY")
    def indicate_discovery(self, pdu):
        """
        Indication signaling to the upper layer the occurence of a discovery operation.
        """
        node_capability = (
            (pdu.channel_normalization_capable << 3) |
            (pdu.security_capable << 2) |
            (pdu.power_source << 1) |
            pdu.node_type
        )

        application_capability = (
            ((pdu.number_of_supported_profiles & 0x02) << 4) |
            ((pdu.number_of_supported_device_types & 0x02) << 1) |
            pdu.user_string_specificied
        )

        return (
            True,
            {
                "source_address" : pdu.source_address,
                "node_capability" : node_capability,
                "vendor_identifier" : pdu.vendor_identifier,
                "vendor_string" : pdu.vendor_string,
                "application_capability" : application_capability,
                "user_string":pdu.user_string if bool(pdu.user_string_specificied) else None,
                "device_type_list":pdu.device_type_list,
                "profile_identifier_list":pdu.profile_identifier_list,
                "requested_device_type":pdu.requested_device_type,
                "link_quality":pdu.link_quality
            }
        )

    @Dot15d4Service.indication("NLME-COMM-STATUS")
    def indicate_comm_status(self, status, pairing_reference=0xFF, pan_id=None, destination_address_mode=MACAddressMode.EXTENDED, destination_address=None):
        """
        Indication signaling to the upper layer the status of the communication.
        """
        return (status,
            {
                "pairing_reference":pairing_reference,
                "pan_id":pan_id,
                "destination_address_mode":destination_address_mode,
                "destination_address":destination_address
            }
        )

    @Dot15d4Service.response("NLME-DISCOVERY")
    def discovery_response(self, status, destination_address, list_of_device_types=[9], list_of_profiles=[192], link_quality=255):
        """
        Response allowing NWK layer to build and transmit a discovery response.
        """
        frame_counter = self.database.get("nwkFrameCounter")
        self.database.set("nwkFrameCounter", frame_counter + 1)

        node_capability =  self.database.get("nwkcNodeCapabilities")
        channel_normalization_capable = (node_capability >> 3) & 1
        security_capable = (node_capability >> 2) & 1
        power_source = "battery_source" if ((node_capability >> 1) & 1) == 0 else "alternating_current_source"
        node_type = "controller" if (node_capability & 1) == 0 else "target"


        # Build a discovery response
        discovery_response = (
            RF4CE_Hdr(
                protocol_version=1,
                security_enabled=0,
                frame_counter=frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Discovery_Response(
                status = int(status),
                channel_normalization_capable = channel_normalization_capable,
                security_capable = security_capable,
                power_source = power_source,
                node_type = node_type,
                vendor_identifier = self.database.get("nwkVendorIdentifier"),
                vendor_string = self.database.get("nwkVendorString"),
                number_of_supported_profiles = len(list_of_profiles),
                profile_identifier_list = list_of_profiles,
                number_of_supported_device_types = len(list_of_device_types),
                device_type_list = list_of_device_types,
                user_string_specificied = int(self.database.get("nwkUserString") is not None),
                user_string = self.database.get("nwkUserString"),
                discovery_req_lqi = link_quality
            )
        )
        ack = self.manager.get_layer('mac').get_service("data").data(
            discovery_response,
            destination_address_mode=MACAddressMode.EXTENDED,
            source_address_mode=MACAddressMode.EXTENDED,
            destination_pan_id=0xFFFF,
            destination_address=destination_address,
            wait_for_ack=True
        )

        self.indicate_comm_status(
            ack,
            0xFF,
            pan_id = 0xFFFF,
            destination_address_mode=MACAddressMode.EXTENDED,
            destination_address=destination_address
        )
        return ack


    @Dot15d4Service.request("NLME-AUTO-DISCOVERY")
    def auto_discovery(self, user_string_specificied=False, list_of_device_types=[9], list_of_profiles=[192], duration=60*50000*(10**6)): # ~ 15s
        """
        Request allowing NWK layer to auto respond to discovery requests.
        """
        duration_us = duration * self.manager.get_layer('phy').symbol_duration

        start = (time()*(10**6))
        match = 0
        while (time()*(10**6)) - start < duration_us:
            try:
                device_type_found = False
                profile_id_found = False

                discovery = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Discovery_Request in pkt, timeout=0.01)

                if discovery.requested_device_type in list_of_device_types:
                    device_type_found = True

                for profile_id in discovery.profile_identifier_list:
                    if profile_id in list_of_profiles:
                        profile_id_found = True
                        break

                if device_type_found and profile_id_found:
                    match += 1
                else:
                    match = 0

                if match == 2:
                    frame_counter = self.database.get("nwkFrameCounter")
                    self.database.set("nwkFrameCounter", frame_counter + 1)

                    node_capability =  self.database.get("nwkcNodeCapabilities")
                    channel_normalization_capable = (node_capability >> 3) & 1
                    security_capable = (node_capability >> 2) & 1
                    power_source = "battery_source" if ((node_capability >> 1) & 1) == 0 else "alternating_current_source"
                    node_type = "controller" if (node_capability & 1) == 0 else "target"

                    # Build a discovery response
                    discovery_response = (
                        RF4CE_Hdr(
                            protocol_version=1,
                            security_enabled=0,
                            frame_counter=frame_counter
                        ) /
                        RF4CE_Command_Hdr() /
                        RF4CE_Cmd_Discovery_Response(
                            status = 0,
                            channel_normalization_capable = channel_normalization_capable,
                            security_capable = security_capable,
                            power_source = power_source,
                            node_type = node_type,
                            vendor_identifier = self.database.get("nwkVendorIdentifier"),
                            vendor_string = self.database.get("nwkVendorString"),
                            number_of_supported_profiles = len(list_of_profiles),
                            profile_identifier_list = list_of_profiles,
                            number_of_supported_device_types = len(list_of_device_types),
                            device_type_list = list_of_device_types,
                            user_string_specificied = int(self.database.get("nwkUserString") is not None),
                            user_string = self.database.get("nwkUserString"),
                            discovery_req_lqi = discovery.link_quality
                        )
                    )

                    ack = self.manager.get_layer('mac').get_service("data").data(
                        discovery_response,
                        destination_address_mode=MACAddressMode.EXTENDED,
                        source_address_mode=MACAddressMode.EXTENDED,
                        destination_pan_id=0xFFFF,
                        destination_address=discovery.source_address,
                        pan_id_suppressed = False,
                        wait_for_ack=True
                    )
                    if ack:
                        return (True, discovery.source_address)
            except NWKTimeoutException:
                pass

        return (False, None)

    @Dot15d4Service.request("NLME-DISCOVERY")
    def discovery(self, destination_address=0xFFFF, destination_pan_id=0xFFFF, list_of_device_types=[1], list_of_profiles=[192], search_device_type=0xFF, list_of_discovered_profiles=[], duration=60*50000*(10**6)):
        """
        Request allowing NWK layer to start a discovery operation.
        """
        node_descriptors = []

        frame_counter = self.database.get("nwkFrameCounter")

        node_capability =  self.database.get("nwkcNodeCapabilities")
        channel_normalization_capable = (node_capability >> 3) & 1
        security_capable = (node_capability >> 2) & 1
        power_source = "battery_source" if ((node_capability >> 1) & 1) == 0 else "alternating_current_source"
        node_type = "controller" if (node_capability & 1) == 0 else "target"

        # Build a discovery response
        discovery_request = (
            RF4CE_Hdr(
                protocol_version=1,
                security_enabled=0,
                frame_counter=frame_counter
            ) /
            RF4CE_Command_Hdr() /
            RF4CE_Cmd_Discovery_Request(
                channel_normalization_capable = channel_normalization_capable,
                security_capable = security_capable,
                power_source = power_source,
                node_type = node_type,
                vendor_identifier = self.database.get("nwkVendorIdentifier"),
                vendor_string = self.database.get("nwkVendorString"),
                number_of_supported_profiles = len(list_of_profiles),
                profile_identifier_list = list_of_profiles,
                number_of_supported_device_types = len(list_of_device_types),
                device_type_list = list_of_device_types,
                user_string_specificied = int(self.database.get("nwkUserString") is not None),
                user_string = self.database.get("nwkUserString"),
                requested_device_type = search_device_type
            )
        )
        for number_of_repetition in range(self.database.get("nwkMaxDiscoveryRepetitions")):
            for channel in [15, 20, 25]:
                frame_counter = self.database.get("nwkFrameCounter")
                self.database.set("nwkFrameCounter", frame_counter + 1)

                discovery_request.frame_counter = frame_counter
                self.manager.get_layer('phy').set_channel(channel)
                ack = self.manager.get_layer('mac').get_service("data").data(
                    discovery_request,
                    destination_address_mode=MACAddressMode.SHORT,
                    source_address_mode=MACAddressMode.EXTENDED,
                    destination_pan_id=destination_pan_id,
                    destination_address=destination_address,
                    pan_id_suppressed = False,
                    wait_for_ack=True
                )
                if ack:
                    try:
                        discovery = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Discovery_Response in pkt, timeout=duration)
                        node_descriptors.append(discovery)
                    except NWKTimeoutException:
                        pass
                sleep(self.database.get("nwkDiscoveryRepetitionInterval") / (50000 * (10**6)))


        return node_descriptors

    def on_command_npdu(self, pdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality=255):
        pdu.link_quality = link_quality
        pdu.source_address = source_address
        pdu.destination_address = destination_address
        pdu.source_pan_id = source_pan_id
        pdu.destination_pan_id = destination_pan_id

        self.add_packet_to_queue(pdu)

        if pdu.command_identifier == 1:
            # If filtering is enabled and link quality is bad, drop
            lqi_threshold = self.manager.database.get("nwkDiscoveryLQIThreshold")
            if lqi_threshold not in (0, 0xFF) and link_quality < lqi_threshold:
                return
            self.indicate_discovery(pdu)

        elif pdu.command_identifier == 3:
            self.indicate_pair(pdu)

@state(NWKIB)
@alias('nwk')
class NWKManager(Dot15d4Manager):
    """
    This class implements the RF4CE Network manager (NWK).
    It handles network-level operations, such as discovery, association or network initiation.

    It exposes two services providing the appropriate API.
    """
    def init(self):
        self.add_service("data", NWKDataService(self))
        self.add_service("management", NWKManagementService(self))

    @source('mac', 'MCPS-DATA')
    def on_mcps_data(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        """
        Callback processing MAC MCPS Data indication.
        """
        pdu.pairing_entry_index = None
        if pdu.security_enabled == 1:
            # if security is enable, check if we have enough info in pairing table
            pairing_table = self.database.get("nwkPairingTable")
            pairing_entry = None
            for candidate_pairing_entry in pairing_table:
                if (
                    (
                        candidate_pairing_entry.destination_ieee_address == source_address or
                        candidate_pairing_entry.destination_network_address == source_address
                    ) and
                    isinstance(candidate_pairing_entry.link_key, bytes) and
                    candidate_pairing_entry.is_active()
                ):
                    pairing_entry = candidate_pairing_entry
                    break

            if pairing_entry is not None:
                success = False
                source_ieee_address = self.get_layer('mac').database.get("macExtendedAddress")

                decryptor = RF4CECryptoManager(pairing_entry.link_key)

                source_address = pack('<Q', pairing_entry.destination_ieee_address)
                destination_address = pack('<Q', source_ieee_address)
                decrypted_packet, success = decryptor.decrypt(pdu, source=source_address, destination=destination_address, rf4ce_only=True)
                if success:
                    pdu = decrypted_packet
                    pdu.pairing_entry_index = pairing_table.index(pairing_entry)
                else:
                    return

        if pdu.frame_type == 1:
            self.get_service('data').on_data_npdu(pdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality)
        elif pdu.frame_type == 2:
            self.get_service('management').on_command_npdu(pdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality)
        elif pdu.frame_type == 3:
            self.get_service('data').on_data_npdu(pdu, source_address, destination_address, source_pan_id, destination_pan_id, link_quality)

NWKManager.add(APLManager)
