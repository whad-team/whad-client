from typing import Tuple
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement
from whad.wirelesshart.connector.link import Link

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
    
class Superframes:
    def __init__(self, sniffer):
        self._sniffer = sniffer
        self.table = {}  # Key = Superframe, Value = list[Link]
        
    def update_from_advertisement(self, dot15d4_pkt):
        try:
            
            for s in dot15d4_pkt[WirelessHart_DataLink_Advertisement].superframes:
                self.add_new_frame(s.superframe_id, s.superframe_number_of_slots)
                for l in s.superframe_links:
                    self.create_and_add_link(s.superframe_id,
                                l.link_join_slot,
                                l.link_channel_offset,
                                dot15d4_pkt.src_addr, 
                                dot15d4_pkt.src_addr,
                                Link.OPTIONS_TRANSMIT if l.link_use_for_transmission else Link.OPTIONS_RECEIVE, 
                                Link.TYPE_JOIN)
        except AttributeError:
            print("Attribute Error")

    def add_new_frame(self, frame_id, frame_nb_slots):
        frame = Superframe(frame_id, frame_nb_slots)
        if frame not in self.table:
            self.table[frame] = []
            self._sniffer.write_modify_superframe(frame.id, frame.nb_slots, frame.flags, frame.launch_asn)
            self._sniffer.linkexplorer.added_superframe(frame)

    def delete_superframe(self, id):
        try:
            self.table.pop(id)
        except KeyError:
            print(f"[Warning] Superframe ID {id} not found in table.")

    def get_frame_by_id(self, frame_id):
        for frame in self.table:
            if frame.id == frame_id:
                return frame
        return None
    
    def get_all_superframes(self):
        return self.table.keys()
    
    def get_links(self, src, neighbor, type= Link.TYPE_NORMAL, options=Link.OPTIONS_RECEIVE)-> Tuple[Superframe, Link]:
        links = []
        for sf in self.get_all_superframes():
            for l in self.get_links_from_superframe(sf.id):
                if l.src==src and l.neighbor==neighbor and l.type==type and l.options==options:
                    links.append((sf, l))
                elif l.src==neighbor and l.neighbor==src and l.type==type and l.options==options:
                    links.append((sf, l))
        return links
    
    def get_link(self, src, neighbor, type= Link.TYPE_NORMAL, options=Link.OPTIONS_RECEIVE)-> Tuple[Superframe, Link]:
        for sf in self.get_all_superframes():
            for l in self.get_links_from_superframe(sf.id):
                if l.src==src and l.neighbor==neighbor and l.type==type and l.options==options:
                    return (sf, l)
                elif l.src==neighbor and l.neighbor==src and l.type==type and l.options==options:
                    return (sf, l)
        return None

    def contains(self, frame_id):
        return self.get_frame_by_id(frame_id) is not None

    def get_links_from_superframe(self, frame_id):
        frame = self.get_frame_by_id(frame_id)
        return self.table.get(frame) if frame else None

    def create_and_add_link(self, frame_id, join_slot, offset, src, neighbor=0xffff, options=None, type=None):
        link = Link(
            src, 
            join_slot, 
            offset, 
            neighbor, 
            options if options is not None else Link.OPTIONS_TRANSMIT,
            type if type is not None else Link.TYPE_NORMAL
        )
        self.add_link(frame_id, link)
        
    def add_link(self, frame_id, link:Link):
        frame = self.get_frame_by_id(frame_id)
        if frame:
            if link not in self.table[frame]:
                self.table[frame].append(link)
                bytesLink = link.getBytesArray()
                bytesLink.insert(0, frame_id)
                self._sniffer.add_links(bytesLink)
            else:
                if link.type==Link.TYPE_BROADCAST or link.type==Link.TYPE_NORMAL:
                    self.table[frame].remove(link)
                    self.table[frame].append(link)
                    bytesLink = link.getBytesArray()
                    bytesLink.insert(0, frame_id)
                    self._sniffer.add_links(bytesLink)
    
    def print_table(self):
        print("superframes:")
        for frame, links in self.table.items():
            print(f"  Frame ID: {frame.id}, links: {links}")

