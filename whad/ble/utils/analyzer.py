from scapy.layers.bluetooth import  ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, \
                                    ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Error_Response
from whad.ble.stack.gatt.message import GattReadByGroupTypeResponse, GattReadByTypeResponse
from whad.ble.profile import PrimaryService, SecondaryService, Characteristic
from whad.ble.profile.attribute import UUID
from struct import unpack

class TrafficAnalyzer:
    def __init__(self):
        self.reset()

    def process_packet(self, packet):
        pass

    def reset(self):
        self.__triggered = False
        self.__completed = False

    def trigger(self):
        self.__triggered = True

    def complete(self):
        self.__completed = True

    @property
    def triggered(self):
        return self.__triggered

    @property
    def completed(self):
        return self.__completed

class ReadByGroupTypeDiscovery(TrafficAnalyzer):

    def reset(self):
        super().reset()
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []

    def process_packet(self, packet):
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

        elif ATT_Read_By_Group_Type_Response in packet and self.triggered:
            response = GattReadByGroupTypeResponse.from_bytes(
                item_size = packet.length,
                data = packet.data
            )
            for item in response:
                self.items.append(item)
                self.handle = item.end + 1
                if item.end == 0xFFFF or item.end == self.end_handle:
                    self.complete()

        elif ATT_Error_Response in packet and packet.request == 0x10 and packet.ecode == 0x0a and self.triggered:
            self.complete()



class ReadByTypeDiscovery(TrafficAnalyzer):

    def reset(self):
        super().reset()
        self.uuid = None
        self.handle = None
        self.start_handle = None
        self.end_handle = None
        self.items = []

    def process_packet(self, packet):
        if ATT_Read_By_Type_Request in packet:
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

        elif ATT_Read_By_Type_Response in packet and self.triggered:
            response = GattReadByTypeResponse.from_bytes(
                item_size = packet[ATT_Read_By_Type_Response].len,
                data = bytes(packet[ATT_Read_By_Type_Response:])[1:]
            )
            for item in response:
                self.items.append(item)
                if item.handle == 0xFFFF or self.handle == self.end_handle:
                    self.complete()

        elif ATT_Error_Response in packet and packet.request == 0x08 and packet.ecode == 0x0a:
            self.complete()

        else:
            pass

class PrimaryServicesDiscovery(ReadByGroupTypeDiscovery):
    def reset(self):
        super().reset()
        self.primary_services = []

    def complete(self):
        if self.uuid == 0x2800:
            for item in self.items:
                print("ITEM:", item.handle, item.end, item.value)
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
    def reset(self):
        super().reset()
        self.characteristics = []

    def complete(self):
        super().complete()
        if self.uuid == 0x2803:
            print(self.items)
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
                print(charac)
                self.characteristics.append(charac)
        else:
            self.reset()

class SecondaryServicesDiscovery(ReadByGroupTypeDiscovery):
    def reset(self):
        super().reset()
        self.secondary_services = []

    def complete(self):
        if self.uuid == 0x2801:
            self.secondary_services = [
                SecondaryService(
                    uuid=UUID(item.value),
                    handle=item.handle,
                    end_handle=item.end
                )
                for item in self.items
            ]
            super().complete()
        else:
            self.reset()

class ServicesDiscovery(TrafficAnalyzer):

    def reset(self):
        super().reset()
        self.primary_service_analyzer = PrimaryServicesDiscovery()
        self.secondary_service_analyzer = SecondaryServicesDiscovery()
        self.services = []

    def complete(self):
        super().complete()
        print(self.services)

    def process_packet(self, pkt):
        self.primary_service_analyzer.process_packet(pkt)
        self.secondary_service_analyzer.process_packet(pkt)

        if self.primary_service_analyzer.triggered:
            self.trigger()

        if self.primary_service_analyzer.completed:
            self.services += self.primary_service_analyzer.primary_services
            self.complete()

        if self.secondary_service_analyzer.completed:
            self.services += self.secondary_service_analyzer.secondary_services
            self.complete()


class GATTServerDiscovery(TrafficAnalyzer):

    def reset(self):
        super().reset()
        self.primary_service_analyzer = PrimaryServicesDiscovery()
        self.secondary_service_analyzer = SecondaryServicesDiscovery()
        self.characteristics_analyzer = CharacteristicsDiscovery()
        self.services = []

    def complete(self):
        super().complete()
        for service in self.services:
            print(service)
            for characteristic in service.characteristics():
                print("\t", characteristic)

    def process_packet(self, pkt):
        self.primary_service_analyzer.process_packet(pkt)
        self.secondary_service_analyzer.process_packet(pkt)
        self.characteristics_analyzer.process_packet(pkt)

        if self.primary_service_analyzer.triggered:
            self.trigger()

        if self.primary_service_analyzer.completed:
            self.services += self.primary_service_analyzer.primary_services
            self.primary_service_analyzer.reset()

        if self.secondary_service_analyzer.completed:
            self.services += self.secondary_service_analyzer.secondary_services
            self.secondary_service_analyzer.reset()

        if self.characteristics_analyzer.completed:
            for characteristic in self.characteristics_analyzer.characteristics:
                for service in self.services:
                    if service.handle < characteristic.handle and characteristic.handle < service.end and characteristic not in service.characteristics():
                        print("Add ", characteristic, "to service", service)
                        service.add_characteristic(characteristic)
                        break
            self.characteristics_analyzer.reset()

        print(self.services)
        for service in self.services:
            service._discovered_characteristics = False
            for characteristic in service.characteristics():
                service._discovered_characteristics = True
                break
            if not service._discovered_characteristics:
                return
        if all([service._discovered_characteristics for service in self.services]):
            self.complete()
