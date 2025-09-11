"""Bluetooth Low Energy traffic analyzers.

This module provides multiple traffic analyzers required by `wanalyze` to process
and analyze BLE packets from PCAP files or live capture. These analyzers are basic
state machines that are fed with packets and return inferred/recovered information.
"""
import json
from struct import unpack

from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_SCAN_RSP, BTLE_CONNECT_REQ
from scapy.layers.bluetooth import  ATT_Read_By_Group_Type_Request, \
    ATT_Read_By_Group_Type_Response, ATT_Read_By_Type_Request, \
    ATT_Read_By_Type_Response, ATT_Error_Response, ATT_Find_Information_Request, \
    ATT_Find_Information_Response

from whad.common.analyzer import TrafficAnalyzer
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.stack.gatt.message import GattReadByGroupTypeResponse, GattReadByTypeResponse, \
    GattFindInfoResponse
from whad.ble.profile.attribute import UUID
from whad.ble.profile import GenericProfile
from whad.ble.profile.characteristic import Characteristic, CharacteristicDescriptor, \
    ClientCharacteristicConfig
from whad.ble.profile.service import PrimaryService, SecondaryService
from whad.ble.crypto import EncryptedSessionInitialization, LegacyPairingCracking, \
    LongTermKeyDistribution, IdentityResolvingKeyDistribution, \
    ConnectionSignatureResolvingKeyDistribution

class PeripheralInformation(TrafficAnalyzer):
    """Peripheral information

    This class processes packets and extract information about devices.
    """

    def __init__(self):
        self.adv_ind_list = []
        self.scan_rsp_list = []
        self.adv_data = None
        self.scan_rsp = None
        self.address = None
        super().__init__()

    def reset(self):
        """Reset this traffic analyzer.
        """
        super().reset()
        self.adv_ind_list = []
        self.scan_rsp_list = []
        self.adv_data = None
        self.scan_rsp = None
        self.address = None

    @property
    def output(self) -> dict:
        """Analyzer output
        """
        if self.scan_rsp is None:
            return {
                "adv_data" : self.adv_data,
                "bd_addr" : str(self.address),
                "addr_type" : self.address.type if self.address is not None else None
            }

        # Include scan response
        return {
            "adv_data" : self.adv_data,
            "scan_rsp" : self.scan_rsp,
            "bd_addr" : str(self.address),
            "addr_type" : self.address.type if self.address is not None else None
        }


    def process_packet(self, packet):
        """Process a specific packet and modify the state of this analyzer.
        """
        if BTLE_ADV_IND in packet:
            self.trigger()
            self.adv_ind_list.append(packet)
        elif BTLE_SCAN_RSP in packet:
            self.trigger()
            self.scan_rsp_list.append(packet)
        elif BTLE_CONNECT_REQ in packet:
            self.trigger()
            self.address = BDAddress(packet.AdvA, random=packet.TxAdd != 0)
            for adv_ind in self.adv_ind_list[::-1]:
                if adv_ind.AdvA == packet.AdvA:
                    self.adv_data = b"".join([bytes(i) for i in adv_ind.data])
                    break
            for scan_rsp in self.adv_ind_list[::-1]:
                if scan_rsp.AdvA == packet.AdvA:
                    self.scan_rsp = b"".join([bytes(i) for i in scan_rsp.data])
                    break
            if self.scan_rsp is not None and self.adv_data is not None:
                self.complete()

class ReadByGroupTypeDiscovery(TrafficAnalyzer):
    """GATT services and characteristics discovery traffic analyzer.
    """

    def __init__(self):
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []

    @property
    def output(self):
        """Current analyzer output state.
        """
        return {
            "uuid" : self.uuid,
            "handle" : self.handle,
            "start_handle" : self.start_handle,
            "end_handle" : self.end_handle,
            "items" : self.items
        }

    def process_packet(self, packet):
        """Modify analyzer state by processing a specific packet.
        """
        if ATT_Read_By_Group_Type_Request in packet:

            if not self.triggered:
                self.start_handle = packet.start
                self.end_handle = packet.end
                self.uuid = packet.uuid
                self.trigger()
            else:
                if packet.end != self.end_handle or packet.uuid != self.uuid:
                    if len(self.items) > 0:
                        self.complete()

                    self.reset()
            self.mark_packet(packet)

        elif ATT_Read_By_Group_Type_Response in packet and self.triggered:
            response = GattReadByGroupTypeResponse.from_bytes(
                item_size = packet.length,
                data = packet.data
            )
            for item in response:
                self.items.append(item)
                self.handle = item.end + 1
                if item.end in  (0xFFFF, self.end_handle):
                    self.complete()

            self.mark_packet(packet)

        elif ATT_Error_Response in packet and packet.request == 0x10 and \
            packet.ecode == 0x0a and self.triggered:
            self.mark_packet(packet)
            self.complete()



class ReadByTypeDiscovery(TrafficAnalyzer):
    """GATT read by type traffic analyzer.
    """

    def __init__(self):
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []


    @property
    def output(self):
        """Output state.
        """
        return {
            "uuid" : self.uuid,
            "handle" : self.handle,
            "start_handle" : self.start_handle,
            "end_handle" : self.end_handle,
            "items" : self.items
        }

    def process_packet(self, packet):
        """Modify analyzer state by processing a specific packet.
        """
        if ATT_Read_By_Type_Request in packet:
            if not self.triggered:
                self.start_handle = packet.start
                self.end_handle = packet.end
                self.uuid = packet.uuid
                self.trigger()
            else:
                if packet.end != self.end_handle or packet.uuid != self.uuid:
                    self.reset()
                    self.start_handle = packet.start
                    self.end_handle = packet.end
                    self.uuid = packet.uuid
                    self.trigger()
            self.mark_packet(packet)

        elif ATT_Read_By_Type_Response in packet and self.triggered:
            response = GattReadByTypeResponse.from_bytes(
                item_size = packet[ATT_Read_By_Type_Response].len,
                data = bytes(packet[ATT_Read_By_Type_Response:])[1:]
            )
            for item in response:
                self.items.append(item)
            self.complete()
            self.mark_packet(packet)
        elif ATT_Error_Response in packet and packet.request == 0x08 and \
            packet.ecode == 0x0a and self.triggered:
            self.complete()
            self.mark_packet(packet)
        else:
            pass

class FindInformationDiscovery(TrafficAnalyzer):
    """GATT device information discovery analyzer.
    """

    def __init__(self):
        self.start_handle = None
        self.end_handle = None
        self.items = []
        super().__init__()

    def reset(self):
        """Reset analyzer.
        """
        super().reset()
        self.start_handle = None
        self.end_handle = None
        self.items = []


    @property
    def output(self):
        """Current analyzer state.
        """
        return {
            "start_handle" : self.start_handle,
            "end_handle" : self.end_handle,
            "items" : self.items
        }

    def process_packet(self, packet):
        """Modify traffic analyzer state by processing a specific packet.
        """
        if ATT_Find_Information_Request in packet:
            if not self.triggered:
                self.start_handle = packet.start
                self.end_handle = packet.end
                self.trigger()
            else:
                if packet.end != self.end_handle:
                    self.reset()
                    self.start_handle = packet.start
                    self.end_handle = packet.end
                    self.trigger()
            self.mark_packet(packet)
        elif ATT_Find_Information_Response in packet and self.triggered:
            response = GattFindInfoResponse.from_bytes(
                format = packet[ATT_Find_Information_Response].format,
                data = bytes(packet[ATT_Find_Information_Response:])[1:]
            )
            for item in response:
                self.items.append(item)
            self.complete()
            self.mark_packet(packet)
        elif ATT_Error_Response in packet and packet.request == 0x04 and self.triggered:
            self.complete()
            self.mark_packet(packet)

class PrimaryServicesDiscovery(ReadByGroupTypeDiscovery):
    """GATT primary services discovery analyzer.
    """

    def __init__(self):
        self.primary_services = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.primary_services = []


    @property
    def output(self):
        """Current analyzer state.
        """
        return {
            "primary_services" : self.primary_services,
        }

    def complete(self):
        """Update output state.
        """
        if self.uuid == 0x2800:
            self.primary_services = [
                PrimaryService(
                    uuid=UUID(item.value),
                    handle=item.handle,
                    end_handle=item.end
                )
                for item in self.items
            ]
            super().complete()
        else:
            self.reset()


class CharacteristicsDiscovery(ReadByTypeDiscovery):
    """GATT characterstics discovery analyzer.
    """

    def __init__(self):
        self.characteristics = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.characteristics = []

    @property
    def output(self):
        """Current analyzer output.
        """
        return {
            "characteristics" : self.characteristics,
        }

    def complete(self):
        """Update output state.
        """
        if self.uuid == 0x2803:
            for item in self.items:
                charac_properties = item.value[0]
                charac_handle = item.handle
                charac_value_handle = unpack('<H', item.value[1:3])[0]
                charac_uuid = UUID(item.value[3:])
                charac = Characteristic(
                    uuid=charac_uuid,
                    properties=charac_properties
                )
                charac.handle = charac_handle
                charac.value_handle = charac_value_handle
                self.characteristics.append(charac)
            super().complete()
        else:
            self.reset()

class SecondaryServicesDiscovery(ReadByGroupTypeDiscovery):
    """GATT secondary services discovery analyzer.
    """

    def __init__(self):
        self.secondary_services = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.secondary_services = []

    @property
    def output(self):
        """Current analyzer output state.
        """
        return {
            "secondary_services" : self.secondary_services,
        }

    def complete(self):
        """Update output state.
        """
        if self.uuid == 0x2801:
            self.secondary_services = [
                SecondaryService(
                    uuid=UUID(item.value),
                    handle=item.handle,
                )
                for item in self.items
            ]
            super().complete()
        else:
            self.reset()

class ServicesDiscovery(TrafficAnalyzer):
    """GATT services discovery.

    This is a high-level analyzer that uses :class:`PrimaryServicesDiscovery` and
    :class:`SecondaryServicesDiscovery` analyzers.
    """

    def __init__(self):
        self.primary_service_analyzer = None
        self.secondary_service_analyzer = None
        self.services = []
        super().__init__()

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.primary_service_analyzer = PrimaryServicesDiscovery()
        self.secondary_service_analyzer = SecondaryServicesDiscovery()
        self.services = []

    @property
    def output(self):
        """Output state.
        """
        return {
            "services" : self.services,
        }

    def process_packet(self, packet):
        """Update sub-analyzers by processing a given packet.
        """
        self.primary_service_analyzer.process_packet(packet)
        self.secondary_service_analyzer.process_packet(packet)

        if self.primary_service_analyzer.triggered:
            self.trigger()

        if self.primary_service_analyzer.completed:
            for pkt in self.primary_service_analyzer.marked_packets:
                self.mark_packet(pkt)
            self.services += self.primary_service_analyzer.primary_services
            self.complete()

        if self.secondary_service_analyzer.completed:
            for pkt in self.secondary_service_analyzer.marked_packets:
                self.mark_packet(pkt)
            self.services += self.secondary_service_analyzer.secondary_services
            self.complete()

class DescriptorsDiscovery(FindInformationDiscovery):
    """GATT descriptors discovery analyzer.
    """

    def reset(self):
        """Reset analyzer state.
        """
        super().reset()
        self.descriptors = []


    @property
    def output(self):
        """Output state
        """
        return {
            "descriptors" : self.descriptors,
        }

    def complete(self):
        """Update output state.
        """
        for item in self.items:
            if item.uuid  == UUID(0x2901) or item.uuid == UUID(0x2902):
                self.descriptors.append(item)

        if len(self.descriptors) > 0:
            super().complete()


class GATTServerDiscovery(TrafficAnalyzer):
    """GATT Server discovery analyzer.

    This analyzer relies on GATT primary/secondary service analyzers as well as
    characteristic and descriptor analyzer to rebuild dynamically a device GATT
    profile from captured packets.
    """

    class InferredProfile(GenericProfile):
        """GATT profile inferred from traffic analysis.
        """

        def __init__(self):
            super().__init__()
            self.devinfo = None

        def export_json(self) -> str:
            """Export inferred profile to JSON file.
            """
            json_value = super().export_json()
            if hasattr(self, "devinfo"):
                profile = json.loads(json_value)
                profile["devinfo"] = self.devinfo
                for k in profile["devinfo"].keys():
                    if isinstance(profile["devinfo"][k], bytes):
                        profile["devinfo"][k] = profile["devinfo"][k].hex()
                json_value = json.dumps(profile)
            return json_value

    def __init__(self):
        self.services_completed = False
        self.characteristics_completed = False
        self.profile = None
        super().__init__()

    def reset(self):
        """Reset analyzer.
        """
        super().reset()
        self.primary_service_analyzer = PrimaryServicesDiscovery()
        self.secondary_service_analyzer = SecondaryServicesDiscovery()
        self.characteristics_analyzer = CharacteristicsDiscovery()
        self.descriptors_discovery = DescriptorsDiscovery()
        self.peripheral_information = PeripheralInformation()

        self.services_completed = False
        self.characteristics_completed = False

        self.profile = None
        self.services = []
        self.characteristics = []
        self.descriptors = []

    @property
    def output(self):
        """Output state
        """
        return {
            "profile" : self.profile
        }

    def complete(self):
        """Update output state
        """
        super().complete()
        self.profile = self.InferredProfile()
        for service in self.services:
            self.profile.add_service(service)
        if self.peripheral_information.completed:
            self.profile.devinfo = self.peripheral_information.output

    def process_packet(self, packet):
        """Update analyzers state by processing a packet.
        """
        self.primary_service_analyzer.process_packet(packet)
        self.secondary_service_analyzer.process_packet(packet)
        self.characteristics_analyzer.process_packet(packet)
        self.descriptors_discovery.process_packet(packet)
        self.peripheral_information.process_packet(packet)


        if self.primary_service_analyzer.triggered:
            self.trigger()

        if self.primary_service_analyzer.completed:

            for pkt in self.primary_service_analyzer.marked_packets:
                self.mark_packet(pkt)

            self.services += self.primary_service_analyzer.primary_services
            self.services_completed = True
            self.primary_service_analyzer.reset()

        if self.secondary_service_analyzer.completed:

            for pkt in self.secondary_service_analyzer.marked_packets:
                self.mark_packet(pkt)

            self.services += self.secondary_service_analyzer.secondary_services
            self.secondary_service_analyzer.reset()

        if self.characteristics_analyzer.completed:

            for pkt in self.characteristics_analyzer.marked_packets:
                self.mark_packet(pkt)

            for characteristic in self.characteristics_analyzer.characteristics:
                for service in self.services:
                    if service.handle < characteristic.handle and \
                            characteristic.handle <= service.end_handle:
                        service.add_characteristic(characteristic)
            self.characteristics_completed = True
            self.characteristics_analyzer.reset()

        if self.descriptors_discovery.completed:

            for pkt in self.descriptors_discovery.marked_packets:
                self.mark_packet(pkt)

            for descriptor in self.descriptors_discovery.descriptors:
                self.descriptors += self.descriptors_discovery.descriptors
                selected_service = None
                for service in self.services:
                    if service.handle < descriptor.handle and \
                            descriptor.handle <= service.end_handle:
                        selected_service = service
                        break

                if selected_service is not None:
                    characteristics = list(selected_service.characteristics())
                else:
                    characteristics = []
                selected_characteristic = None
                for characteristic in characteristics:
                    if characteristic.handle <= descriptor.handle:
                        selected_characteristic = characteristic
                    else:
                        break
                if selected_characteristic is not None:
                    descriptor_obj = None
                    if descriptor.uuid  == UUID(0x2901):
                        descriptor_obj = CharacteristicDescriptor(
                                selected_characteristic,
                                handle=descriptor.handle,
                                uuid=descriptor.uuid
                        )
                    elif descriptor.uuid == UUID(0x2902):
                        descriptor_obj = ClientCharacteristicConfig(
                                selected_characteristic,
                                handle=descriptor.handle
                        )
                    if descriptor_obj is not None:
                        selected_characteristic.add_descriptor(descriptor_obj)

            self.descriptors_discovery.reset()


        if (self.triggered and
            self.characteristics_completed and
            not self.characteristics_analyzer.triggered and
            self.services_completed and
            not self.primary_service_analyzer.triggered and
            not self.descriptors_discovery.triggered
        ):
            handles = []
            for service in self.services:
                handles.append(service.handle)
                for characteristic in service.characteristics():
                    handles.append(characteristic.handle)
                    handles.append(characteristic.value_handle)

                    for descriptor in characteristic.descriptors():
                        handles.append(descriptor.handle)

                    if characteristic.can_notify() or characteristic.can_indicate():
                        if len(list(characteristic.descriptors())) == 0:
                            return

            if (
                    all([len(list(service.characteristics())) > 0 for service in self.services]) and
                    list(range(min(*handles), max(*handles)+1)) == handles
                ):
                self.complete()


analyzers = {
    "peripheral_information" : PeripheralInformation,
    "encrypted_session_initialization" : EncryptedSessionInitialization,
    "legacy_pairing_cracking" : LegacyPairingCracking,
    "ltk_distribution" : LongTermKeyDistribution,
    "irk_distribution" : IdentityResolvingKeyDistribution,
    "csrk_distribution" : ConnectionSignatureResolvingKeyDistribution,
    "profile_discovery" : GATTServerDiscovery
}
