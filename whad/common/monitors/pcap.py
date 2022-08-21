from whad.common.monitors import WhadMonitor
from scapy.utils import PcapWriter,PcapReader
from os.path import exists
from scapy.all import BTLE_RF
from time import time

class PcapWriterMonitor(WhadMonitor):
    def __init__(self, pcap_file, monitor_reception=True, monitor_transmission=True):
        super().__init__(monitor_reception, monitor_transmission)
        self._pcap_file = pcap_file
        self._writer = None
        self._formatter = None
        self._reference_time = None
        self._start_time = None

    def setup(self):
        existing_pcap_file = exists(self._pcap_file)
        if existing_pcap_file:
            print("[i] PCAP file %s exists, appending new packets."  % self._pcap_file)
            # We collect the first packet timestamp to use it as reference time
            self._start_time = PcapReader(self._pcap_file).read_packet().time * 1000000

        self._writer = PcapWriter(self._pcap_file, append=existing_pcap_file)

        self._formatter = self.default_formatter
        if (
            hasattr(self._connector, "format") and
            callable(getattr(self._connector, "format"))
        ):
            self._formatter = getattr(self._connector, "format")

    def close(self):
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    def default_formatter(self, packet):
        if (
            hasattr(packet, "metadata") and
            hasattr(packet.metadata, "timestamp")
        ):
            return packet, packet.metadata.timestamp
        else:
            return packet, None

    def process_packet(self, packet):
        if self._processing:
            now = time() * 1000000
            packet, timestamp = self._formatter(packet)

            # Relative time synchronization
            if timestamp is None:
                timestamp = now

            # Process accurate timestamp if available, else use local clock
            if self._reference_time is None:
                if self._start_time is None:
                    self._reference_time = (now, timestamp)
                else:
                    self._reference_time = (self._start_time, timestamp - (now - self._start_time))
                timestamp = now
            else:
                timestamp = self._reference_time[0] + (timestamp - self._reference_time[1])

            # Convert timestamp to second (float)
            packet.time = timestamp / 1000000
            self._writer.write(packet)
