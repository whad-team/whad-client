from whad.common.monitors import WhadMonitor
from scapy.all import conf
from scapy.layers.bluetooth4LE import *
from scapy.utils import PcapWriter,PcapReader
from os.path import exists
from whad.common.pcap import patch_pcap_metadata, extract_pcap_metadata
from time import time
from os import stat, remove
from stat import S_ISFIFO
from threading import Lock

import logging
logger = logging.getLogger(__name__)

class PcapWriterMonitor(WhadMonitor):
    """
    PcapWriterMonitor.

    Monitor allowing to export the traffic transmitted and received by the
    targeted connector to a PCAP file with appropriate header.

    :Usage:

        >>> monitor = PcapWriterMonitor("mypcapfile.pcap")
        >>> monitor.attach(connector)
        >>> monitor.start()

    """
    def __init__(self, pcap_file, monitor_reception=True, monitor_transmission=True):
        super().__init__(monitor_reception, monitor_transmission)
        self._pcap_file = pcap_file
        self._writer = None
        self._formatter = None
        self._reference_time = None
        self._start_time = None
        self._nb_pkts_written = 0
        self._writer_lock = Lock()


    @property
    def packets_written(self):
        '''Return the number of packets already written
        '''
        return self._nb_pkts_written


    def setup(self):
        # First, we check if the pcap already exists
        existing_pcap_file = exists(self._pcap_file)
        sync = False
        # If it exists, we have two cases:
        # - it is a named pipe and we have to provide sync=True to PcapWriter
        # - it is an already existing pcap file and we have to provide append=True to PcapWriter

        if existing_pcap_file:
            # Checks if it is a named FIFO
            if S_ISFIFO(stat(self._pcap_file).st_mode):
                logger.info("[i] Named pipe %s detected, syncing." % self._pcap_file)
                sync = True
            else:
                # Checks if it is an already existing pcap file.
                logger.info("[i] PCAP file %s exists, appending new packets."  % self._pcap_file)
                try:
                    # We collect the first packet timestamp to use it as reference time
                    self._start_time = PcapReader(self._pcap_file).read_packet().time * 1000000
                except EOFError:
                    # Pcap is empty, remove it and open a new one
                    remove(self._pcap_file)
                    existing_pcap_file = False

        # Instanciate the PCAP Writer with the appropriate parameters
        self._writer_lock.acquire()
        self._writer = PcapWriter(
                                    self._pcap_file,
                                    append=existing_pcap_file and not sync,
                                    sync=sync
        )
        self._writer_lock.release()

        # Checks if there is a scapy packet formatter associated with the connector.
        # A formatter allows to describe manually how to build the packet, it is mainly
        # useful to populate a relevant header for PCAP export.
        self._formatter = self.default_formatter
        if (
            hasattr(self._connector, "format") and
            callable(getattr(self._connector, "format"))
        ):
            self._formatter = getattr(self._connector, "format")


    def close(self):
        # Acquire lock on writer
        self._writer_lock.acquire()
        if hasattr(self, "_writer") and self._writer is not None:


            # Close writer
            try:
                self._writer.close()
                patch_pcap_metadata(self._pcap_file, self._connector.domain)

            except BrokenPipeError:
                pass

            # Mark writer as not available anymore
            self._writer = None

        # Release lock on writer
        self._writer_lock.release()


    def default_formatter(self, packet):
        """
        Formatter used by default, if no formatter is found in the targeted connector.
        It only extracts the accurate timestamp if one is available in metadata.
        """
        if (
            hasattr(packet, "metadata") and
            hasattr(packet.metadata, "timestamp")
        ):
            return packet, packet.metadata.timestamp
        else:
            return packet, None

    def process_packet(self, packet):
        # Acquire lock on writer lock acquire multithread error

        self._writer_lock.acquire()

        if self._processing:
            # Note the current local clock timestamp in us
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
            try:
                if self._writer is not None:
                    # Write packet
                    self._writer.write(packet)
                    self._nb_pkts_written += 1
                else:
                    # We are trying to write to a closed PCAP monitor,
                    # issue a warning message
                    logger.warning('cannot write to PCAP: file has already been closed')
            except BrokenPipeError:
                pass
        # Release lock
        self._writer_lock.release()
