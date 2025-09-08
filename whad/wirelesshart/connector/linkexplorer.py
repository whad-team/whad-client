from collections import defaultdict
import threading
from time import sleep
from whad.dot15d4.connector import Dot15d4FCS
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
        self._running = True
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._monitor_communications, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._thread.join()

    def added_superframe(self, sf: Superframe):
        """This method updates the communication table length based on the new superframe"""
        self._superframes_info = [item for item in self._superframes_info if item[1] != sf.id]
        self._superframes_info.append((sf.nb_slots, sf.id))
        self._superframes_info = sorted(self._superframes_info, key=lambda x: x[0], reverse=True)
        self._discovered_communication = [[None, 0, -1] for _ in range(self._superframes_info[0][0])] # initializing 
       
    def delete_superframe(self, sf_id):
       self._superframes_info = [item for item in self._superframes_info if item[1] != sf_id]
       
    def discovered_communication(self, pdu:bytes, slot, offset):
        """
        Called when the sniffer receives an unexpected communication between two nodes.
        """
        pkt = Dot15d4FCS(pdu)
                
        #create link
        link = Link(pkt.src, slot, offset, pkt.dest, type=Link.TYPE_DISCOVERY)

        with self._lock:
            if slot > len(self._discovered_communication):
                return
            #adding the link to the discovered communication
            existing_com = self._discovered_communication[slot]
            existing_link = existing_com[0]
            
            if existing_link == link:
                existing_com[1] += 1 # got one more communication on this slot
                if existing_link.src == link.neighbor :
                    existing_link.options = Link.OPTIONS_SHARED # as we already sniffed the two parts speak => shared link
            else : # first time we listen on this slot => initialize all
                self._discovered_communication[slot] = [link, 1, self._superframes_info[0][1]] # initialize this slot
                
                
            # try to detect if the link fits a smaller superframe pattern
            sf_info = self._superframes_info[0]
            for next_sf_info in self._superframes_info[1:]:
                delta = next_sf_info[0]
                while delta < sf_info[0]:
                    index = (slot + delta) % sf_info[0]
                    next_com = self._discovered_communication[index]
                    next_link = next_com[0]
                    if link.equals_modulo(next_link, next_sf_info[0]):
                        #merging the two communications into current
                        self._discovered_communication[slot][1] += next_com[1] #occurences
                        self._discovered_communication[slot][2] = max(self._discovered_communication[slot][2],
                                                                      next_com[2], 
                                                                      next_sf_info[1]) # superfrmae id

                        if link.src == next_link.neighbor : #updating link
                            link.options = Link.OPTIONS_SHARED
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
                            self._discovered_communication[i] = [None, 0, -1]
                        elif c[1]==0:
                            self._discovered_communication[i] = [None, 0, -1]
                        else:
                            self._discovered_communication[i][1]-=1
