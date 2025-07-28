from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement
from whad.wirelesshart.connector.link import Link


class Superframes:
    def __init__(self, sniffer):
        self._sniffer = sniffer
        self.table = {}  # Key = Superframe, Value = list[Link]
        
    def update_from_advertisement(self, dot15d4_pkt):
        for s in dot15d4_pkt[WirelessHart_DataLink_Advertisement].superframes:
            self.add_new_frame(s.superframe_id, s.superframe_number_of_slots)
            for l in s.superframe_links:
                self.add_link(s.superframe_id, l.link_join_slot, l.link_channel_offset)

    def add_new_frame(self, frame_id, frame_nb_slots):
        frame = Superframe(frame_id, frame_nb_slots)
        if frame not in self.table:
            self.table[frame] = []
            self._sniffer.write_modify_superframe(frame.id, frame.nb_slots, frame.flags, frame.launch_asn)

    def get_frame_by_id(self, frame_id):
        for frame in self.table:
            if frame.id == frame_id:
                return frame
        return None

    def contains(self, frame_id):
        return self.get_frame_by_id(frame_id) is not None

    def get_links(self, frame_id):
        frame = self.get_frame_by_id(frame_id)
        return self.table.get(frame) if frame else None

    def add_link(self, frame_id, join_slot, offset, src=0x0000, neighbor=0xffff, options=0x4, type=0x1):
        frame = self.get_frame_by_id(frame_id)
        if frame:
            link = Link(src, join_slot, offset, neighbor, options, type)
            if link not in self.table[frame]:
                self.table[frame].append(link)
                bytesLink = link.getBytesArray()
                bytesLink.insert(0, frame_id)
                self._sniffer.add_links(bytesLink)
    
    def print_table(self):
        print("superframes:")
        for frame, links in self.table.items():
            print(f"  Frame ID: {frame.id}, links: {links}")


class Superframe:   
    def __init__(self, id, nb_slots, flags=0x1, launch_asn=None):
        self.id = id
        self.nb_slots = nb_slots
        self.flags = flags
        self.launch_asn = launch_asn 
        
    def __eq__(self, other):
        return isinstance(other, Superframe) and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        return f"Superframe(id={self.id}, slots={self.nb_slots})"