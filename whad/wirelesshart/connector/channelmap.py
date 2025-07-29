from threading import RLock
import struct

from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

def channel_map_mutex(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_chan_map()
        result = f(self, *args, **kwargs)
        self.unlock_chan_map()
        return result

    return _wrapper

class ChannelMap:
    """
    This class permits the following of the activated channels on which the network communicates
    """
    def __init__(self, list=[]):
        self.list = list
        self.channel_map = bytes(0xffff)
        self.__mutex = RLock()
        
    def lock_chan_map(self):
        self.__mutex.acquire()

    def unlock_chan_map(self):
        self.__mutex.release()
    
    @channel_map_mutex
    def get_list(self):
        return self.list
    
    @channel_map_mutex
    def set_list(self, list):
        self.list = list
    
    def update_from_advertisement(self, pkt):
        """
        This method updates the channel map when listening to an advertising
        """
        if self.channel_map != struct.unpack("<H", bytes(pkt[WirelessHart_DataLink_Advertisement].channel_map))[0]:
                channel_map = bytes(pkt[WirelessHart_DataLink_Advertisement].channel_map)
                channel_map = struct.unpack("<H", channel_map)[0]
                binary_channel_map = bin(channel_map)[2:].zfill(16)
                self.update_list(binary_channel_map)
                #print("Channel map has changed:")
                #print("updating channel map dongle:", channel_map)
                #print("channel_map:", hex(channel_map))
                #print("binary_channel_map: ", binary_channel_map)
                #print("channel_list:", self.get_list())
    
    @channel_map_mutex
    def update_list(self, binary_map):
        updated_list = [idx+11 for idx, bit in enumerate(reversed(binary_map)) if bit == '1']
        if self.get_list() != updated_list :
            self.set_list(updated_list)