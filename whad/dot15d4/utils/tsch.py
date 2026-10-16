from typing import List, Dict, Tuple, Optional
from whad.hub.dot15d4 import LinkOptions, LinkType
from whad.scapy.layers import Superframe as PktSuperframe, Link as PktLink

class Link:
    def __init__(
        self, 
        source: int, 
        time_slot: int, 
        channel_offset: int, 
        neighbor: int = 0xFFFF, 
        options: LinkOptions = LinkOptions.RECEIVE, 
        link_type: LinkType = LinkType.NORMAL
    ):
        self.source = source
        self.time_slot = time_slot
        self.channel_offset = channel_offset
        self.neighbor = neighbor

        self.options = LinkOptions(options)
        self.link_type = LinkType(link_type)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Link):
            return False
        return self.time_slot == other.time_slot and self.channel_offset == other.channel_offset

    def __repr__(self) -> str:
        return (f"Link(slot={self.time_slot}, offset={self.channel_offset}, "
                f"type={self.link_type.name}, options={self.options.name})")

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "time_slot": self.time_slot,
            "channel_offset": self.channel_offset,
            "neighbor": self.neighbor,
            "options": self.options.name,
            "link_type": self.link_type.name
        }

    def to_pkt(self) -> PktLink : 
        return PktLink(
            link_join_slot=self.time_slot,
            link_reserved=0,
            link_use_for_transmission= 1 if (self.options==LinkOptions.SHARED or self.options==LinkOptions.TRANSMIT) else 0,
            link_channel_offset=self.channel_offset
        )


class Superframe:   
    def __init__(self, superframe_id: int, number_of_slots: int, flags: int = 0x0, asn: int = 0):
        self.id = superframe_id
        self.number_of_slots = number_of_slots
        self.flags = flags
        self.asn = asn
        self.links: List[Link] = []

    def __eq__(self, other) -> bool:
        if not isinstance(other, Superframe):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"Superframe(id={self.id}, slots={self.number_of_slots}, links={len(self.links)})"

    def to_dict(self) -> Dict:
        return {
            "superframe_id": self.id,
            "number_of_slots": self.number_of_slots,
            "flags": self.flags,
            "asn": self.asn,
            "links": [link.to_dict() for link in self.links]
        }

    def to_pkt(self) -> PktSuperframe:
        return PktSuperframe(
            superframe_id=self.id,
            superframe_number_of_slots=self.number_of_slots,
            superframe_number_of_links=len(self.links),
            superframe_links=[l.to_pkt() for l in self.links]
        )


class Network:
    def __init__(self):
        self.superframes: Dict[int, Superframe] = {}
        self.asn = 0
        self._channel_map = None

    @property
    def channel_map(self):
        return self._channel_map

    @channel_map.setter
    def channel_map(self, channel_map):
        self._channel_map = channel_map

    def clear(self):
        self.superframes.clear()

    def add_or_update_superframe(self, superframe_id: int, number_of_slots: int, flags: int = 0, asn: int = 0):
        if superframe_id in self.superframes:
            sf = self.superframes[superframe_id]
            sf.number_of_slots = number_of_slots
            sf.flags = flags
            sf.asn = asn
        else:
            self.superframes[superframe_id] = Superframe(superframe_id, number_of_slots, flags, asn)

    def remove_superframe(self, superframe_id: int):
        if superframe_id in self.superframes:
            del self.superframes[superframe_id]

    def add_link(self, superframe_id: int, source: int, time_slot: int, channel_offset: int, neighbor: int, options: LinkOptions, link_type: LinkType):
        if superframe_id not in self.superframes:
            return
        sf = self.superframes[superframe_id]
        new_link = Link(source, time_slot, channel_offset, neighbor, options, link_type)
        if new_link in sf.links:
            sf.links.remove(new_link)
        sf.links.append(new_link)

    def remove_link(self, superframe_id: int, time_slot: int, channel_offset: int):
        if superframe_id not in self.superframes:
            return
        sf = self.superframes[superframe_id]
        target = next((l for l in sf.links if l.time_slot == time_slot and l.channel_offset == channel_offset), None)
        if target:
            sf.links.remove(target)

    def get_link(self, src: int, neighbor: int, link_type: LinkType = LinkType.NORMAL, options: LinkOptions = LinkOptions.RECEIVE) -> Optional[Tuple[Superframe, Link]]:
        for sf in self.superframes.values():
            for l in sf.links:
                if l.link_type == LinkType.BROADCAST:
                    if (((l.source == src and l.neighbor == 0xFFFF) or (l.neighbor == src and l.source == 0xFFFF)) and l.options == options):
                        return (sf, l)
                elif l.source == src and l.neighbor == neighbor and l.link_type == link_type and l.options == options:
                    return (sf, l)
                elif l.source == neighbor and l.neighbor == src and l.link_type == link_type:
                    if options == LinkOptions.TRANSMIT and l.options == LinkOptions.RECEIVE:
                        return (sf, l)
                    elif options == LinkOptions.RECEIVE and l.options == LinkOptions.TRANSMIT:
                        return (sf, l)
        return None

    def __repr__(self) -> str:
        lines = ["TSCH Network"]
        
        if not self.superframes:
            lines.append("  [Empty]")
            return "\n".join(lines)

        for sf in self.superframes.values():
            lines.append(f"{sf}")
            if not sf.links:
                lines.append("  └── (No links configured)")
            for link in sf.links:
                lines.append(f"  └── {link}")
                
        return "\n".join(lines)