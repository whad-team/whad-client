
"""
WHAD traffic analyzer base module.
"""
from typing import List
from scapy.packet import Packet


class TrafficAnalyzer:
    """
    Traffic analyzer base class.

    This class must be inherited by specialized traffic analyzers
    in order to provide `wanalyze` with extracted and/or computed
    data.
    """

    def __init__(self):
        self.reset()

    def process_packet(self, packet):
        """Process a packet.
        """

    def mark_packet(self, packet):
        """Mark a specific packet.
        """
        self.__marked_packets.append(packet)

    def reset(self):
        """Reset traffic analyzer state.
        """
        self.__triggered = False
        self.__completed = False
        self.__marked_packets = []

    def trigger(self):
        """Trigger this traffic analyzer.
        """
        self.__triggered = True

    def complete(self):
        """Mark this analyzer as completed.

        Once a traffic analyzer is completed, its output
        can be queried.
        """
        self.__completed = True

    @property
    def marked_packets(self) -> List[Packet]:
        """Returns marked packets.
        """
        return self.__marked_packets

    @property
    def output(self):
        """Returns the traffic analyzer output.
        """
        return None

    @property
    def triggered(self) -> bool:
        """Determine if the traffic analyzer has been triggered.

        :return-type: bool
        :return: `True` if triggered, `False` otherwise.
        """
        return self.__triggered

    @property
    def completed(self) -> bool:
        """Determine if the traffic analyzer has completed is
        job.

        :return-type: bool
        :return: `True` if completed, `False` otherwise.
        """
        return self.__completed
