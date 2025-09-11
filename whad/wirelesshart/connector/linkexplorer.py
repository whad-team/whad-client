from collections import defaultdict
import threading
from time import sleep
from whad.dot15d4.connector import Dot15d4FCS
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement
from whad.wirelesshart.connector.link import Link
from whad.wirelesshart.connector.superframes import Superframe


class LinkExplorer():
    """
    This class permits the discovery of already existing links before the start of the sniffer or the links 
    the sniffer has missed for an unknown reason
    """
    def __init__(self, sniffer):
        self.sniffer = sniffer
        # Type : list [(length, id)] of all superframes saved in decreasing order of length
        self._superframes_info = [] 
        # list of length=max_superframe_length of the discovered communications [(Link, nb_of_heard_pkts, sf_id)]        
        self._discovered_communication = [] 
        self._running = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._monitor_communications, daemon=True)
        
    def start(self):
        self._running = True
        self._thread.start()

    def stop(self):
        self._running = False
        self._thread.join()

    def added_superframe(self, sf: Superframe):
        """This method updates the communication table length based on the new superframe"""
        self._superframes_info = [item for item in self._superframes_info if item[1] != sf.id] #keep superframes all superframes except hte one given as parameter
        self._superframes_info.append((sf.nb_slots, sf.id)) # add the superframe given
        self._superframes_info = sorted(self._superframes_info, key=lambda x: x[0], reverse=True) # sort by decreasing superframe length 
        self._discovered_communication = [[None, 0, -1] for _ in range(self._superframes_info[0][0])] # initializing a list of [link:None, nb_of_heard_pkts:0, sf_id-1] of the length of the biggest sf 
       
    def delete_superframe(self, sf_id):
       self._superframes_info = [item for item in self._superframes_info if item[1] != sf_id] #keep all sf except the one to delete
       
    def discovered_communication(self, pdu:bytes, slot, offset):
        """
        Called when the sniffer receives an unexpected communication between two nodes.
        """
        pkt = Dot15d4FCS(pdu) # cast bytes into dot15d4 pkt
        try:
            #detect type
            if WirelessHart_DataLink_Advertisement in pkt:
                type = Link.TYPE_DISCOVERY
            elif pkt.fcf_srcaddrmode == "Long" or pkt.fcf_destaddrmode == "Long":
                type = Link.TYPE_JOIN
            elif pkt.dest_addr == 0xFFFF:
                type = Link.TYPE_BROADCAST
            else:
                type = Link.TYPE_NORMAL
            
        except AttributeError:
            print("value error:", pkt)
            print("bytes:", bytes(pkt).hex())
            pkt.show()
                
        #create link
        link = Link(pkt.src_addr, slot, offset, pkt.dest_addr, type=type)

        with self._lock:
            # if slot > length of the biggest superframe => the length will certainly be updated later by the butterfly cmnds
            if slot > len(self._discovered_communication):
                #ignore for now
                return
            #adding the link to the discovered communication
            existing_com = self._discovered_communication[slot] # existing_com = (link, nb_of_heard_pkts, sf_id)
            existing_link = existing_com[0] # the link already discovered , None otherwise
            
            if existing_link == link: # the discovered link corresponds to the existing : same slot, same offset
                existing_com[1] += 1 # got one more communication on this slot, increment nb of heard pkts
                
                #fine graining link parameters
                
                if existing_link.src == link.neighbor :
                    existing_link.options = Link.OPTIONS_SHARED # as we already sniffed the two parts speak => shared link
                # type priority : Normal, Broadcast, join, discovery => update type with the strongest type of the two
                if existing_link.type == Link.TYPE_NORMAL or link.type == Link.TYPE_NORMAL:
                    self._discovered_communication[slot][0].type = Link.TYPE_NORMAL
                elif existing_link.type == Link.TYPE_BROADCAST or link.type == Link.TYPE_BROADCAST:
                    self._discovered_communication[slot][0].type = Link.TYPE_BROADCAST
                elif existing_link.type == Link.TYPE_JOIN or link.type == Link.TYPE_JOIN:
                    self._discovered_communication[slot][0].type = Link.TYPE_JOIN
                    
            else : # first time we listen on this slot => initialize all
                self._discovered_communication[slot] = [link, 1, self._superframes_info[0][1]] # initialize this slot to the biggest sf id
                
                
            # try to detect if the link fits a smaller superframe pattern
            sf_info = self._superframes_info[0]
            for next_sf_info in self._superframes_info[1:]: # for every superframe
                delta = next_sf_info[0] # initial length
                while delta < sf_info[0]: # while detla < max length 
                    index = (slot + delta) % sf_info[0] # take the join slot corresponding the the sf
                    next_com = self._discovered_communication[index]
                    next_link = next_com[0]
                    if link.equals_modulo(next_link, next_sf_info[0]): # if next_link corresponds to the link discoverd % length
                        #merging the two communications into current
                        self._discovered_communication[slot][1] += next_com[1] #occurences
                        self._discovered_communication[slot][2] = max(self._discovered_communication[slot][2],
                                                                      next_com[2], 
                                                                      next_sf_info[1]) # superframe id

                        #updating link caracteristics
                        if link.src == next_link.neighbor :
                            link.options = Link.OPTIONS_SHARED
                        if existing_link:
                            if existing_link.type == Link.TYPE_NORMAL or link.type == Link.TYPE_NORMAL:
                                self._discovered_communication[slot][0].type = Link.TYPE_NORMAL
                            elif existing_link.type == Link.TYPE_BROADCAST or link.type == Link.TYPE_BROADCAST:
                                self._discovered_communication[slot][0].type = Link.TYPE_BROADCAST
                            elif existing_link.type == Link.TYPE_JOIN or link.type == Link.TYPE_JOIN:
                                self._discovered_communication[slot][0].type = Link.TYPE_JOIN
                        # delete the communication at index as it is added by discovered link
                        self._discovered_communication[index] = [None, 0, -1]
                    delta += next_sf_info[0] #next modulo slot
                sf_info = next_sf_info #next superframe
            

    def _monitor_communications(self):
        """this method checks if some communications have been confirmed as links and sends command to the dongle"""
        while self._running:
            sleep(10*len(self._superframes_info))
            with self._lock:
                for i, c in enumerate(self._discovered_communication):
                    if c != [None, 0, -1]:
                        if c[1]>1:
                            c[0].join_slot = c[0].join_slot % self.sniffer.superframes.get_frame_by_id(c[2]).nb_slots
                            self.sniffer.superframes.add_link(c[2],c[0])
                            print(f"add discovered link: {c[0]} at sf :{c[2]}")
                            self._discovered_communication[i] = [None, 0, -1]
                        elif c[1]==0:
                            self._discovered_communication[i] = [None, 0, -1]
                        else:
                            self._discovered_communication[i][1]-=1
