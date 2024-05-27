import json
from scapy.all import Packet_metaclass
from importlib import import_module

class IPCConverter:
    def __init__(self, *args):
        self.data = args

    def to_dump(self):
        if len(self.data) == 1:
            return IPCPacket(self.data[0]).to_dump()
        elif len(self.data) == 3:
            return IPCDisplayFormat(*self.data).to_dump()

    @classmethod
    def from_dump(cls, dump):
        data = json.loads(dump)
        if data["type"] == "packet":
            return IPCPacket.from_dump(dump)
        elif data["type"] == "formatter":
            return IPCDisplayFormat.from_dump(dump)

class IPCPacket:
    def __init__(self, packet):
        self.packet = packet

    def to_dump(self):
        packet = {
            "type":"packet",
            "packet":bytes(self.packet).hex(),
            "packet_class": (self.packet.__class__.__module__, self.packet.__class__.__name__),
            "metadata":self.packet.metadata.__dict__,
            "metadata_class":(self.packet.metadata.__class__.__module__, self.packet.metadata.__class__.__name__)
        }
        return json.dumps(packet, default=lambda o : o.__dict__)

    @classmethod
    def from_dump(cls, dump):
        data = json.loads(dump)
        packet_module, packet_name = data["packet_class"]
        packet_class = getattr(import_module(packet_module), packet_name)
        metadata_module, metadata_name = data["metadata_class"]
        metadata_class = getattr(import_module(metadata_module), metadata_name)
        pkt = packet_class(bytes.fromhex(data["packet"]))
        pkt.metadata = metadata_class(**data["metadata"])
        return pkt


class IPCDisplayFormat:
    def __init__(self, format, metadata, color):
        self.format = format
        self.metadata = metadata
        self.color = color

    def to_dump(self):
        formatter = {
            "type":"formatter",
            "format" : self.format,
            "metadata" : self.metadata,
            "color" : self.color
        }
        return json.dumps(formatter, default=lambda o : o.__dict__)

    @classmethod
    def from_dump(cls, dump):
        data = json.loads(dump)
        return (data["format"], data["metadata"], data["color"])
