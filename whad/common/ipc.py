import json
from importlib import import_module

class IPCPacket:
    def __init__(self, packet):
        self.packet = packet

    def to_dump(self):
        packet = {
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
