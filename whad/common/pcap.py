"""Multi-domain PCAP reader
"""
from time import sleep
from scapy.utils import rdpcap

from whad.scapy.layers import *

class PCAPReader(object):

    def __init__(self, pcapfile : str):
        """Initialize a multi-domain PCAP layer
        """
        # Load packets from PCAP file
        self.__packets = rdpcap(pcapfile)

    def packets(self, start=0, count=None, accurate=True, offset=0.0, exclude=[], filter=lambda x: True):
        """Filter packets from PCAP file and yields them.

        :param start: Start position in the PCAP
        :type start: int
        :param count: Number of packets to return
        :type count: int
        :param filter: Lambda function used to filter packets. By default, keeps everything.
        :type filter: lambda
        """
        timestamp = None
        if count is None:
            for pos, packet in enumerate(self.__packets[start:]):
                # Packet must be excluded ?
                if (pos+1) in exclude:
                    # continue
                    #timestamp = float(packet.time)
                    continue

                # Process packet
                if timestamp is None:
                    timestamp = float(packet.time)
                else:
                    delay = float(packet.time) - timestamp
                    timestamp = float(packet.time)
                    if accurate:
                        sleep(delay + offset)

                if filter(packet):
                    yield packet
        else:
            for packet in self.__packets[start:start+count]:
                
                # Packet must be excluded ?
                if (pos+1) in exclude:
                    # continue
                    #timestamp = float(packet.time)
                    continue

                # Process packet
                if timestamp is None:
                    timestamp = float(packet.time)
                else:
                    delay = float(packet.time) - timestamp
                    timestamp = float(packet.time)
                    if accurate:
                        sleep(delay+offset)
                if filter(packet):
                    yield packet