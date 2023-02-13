import logging
from whad.device import WhadDeviceConnector

logger = logging.getLogger(__name__)

class WhadMonitor:
    """
    Whad Monitor.

    A monitor is an object allowing to monitor the packets received and/or transmitted by a given
    connector. It can be attached to the target connector, and performs a specific action when a
    monitored packet is received or transmitted.
    """
    def __init__(self, monitor_reception=True, monitor_transmission=True):
        self._connector = None
        self.__monitor_reception = monitor_reception
        self.__monitor_transmission = monitor_transmission
        self.__setup_done = False
        self._processing = False

    def attach(self, connector):
        """
        Attachs the current monitor to a specific connector.

        :param connector: WhadConnector to monitor
        :returns: boolean indicating the success of attach operation
        """
        success = False
        if isinstance(connector, WhadDeviceConnector):
            self._connector = connector
            if self.__monitor_reception:
                self._connector.attach_callback(self.process_packet, on_reception = True)
                #print("[i] reception callback attached.")
                logger.debug("monitor: reception callback attached.")
                success = True

            if self.__monitor_transmission:
                self._connector.attach_callback(self.process_packet, on_transmission = True)
                #print("[i] transmission callback attached.")
                logger.debug("monitor: transmission callback attached.")
                success = True
        return success

    def detach(self):
        """
        Detachs the current monitor from the previously attached connector.

        :returns: boolean indicating the success of detach operation
        """
        logger.debug("monitor: detaching callbacks.")
        success = False
        if self._connector is not None:
            if self.__monitor_reception:
                self._connector.detach_callback(self.process_packet, on_reception = True)
                success = True
            if self.__monitor_transmission:
                self._connector.detach_callback(self.process_packet, on_transmission = True)
                success = True
        return success

    def setup(self):
        """
        Performs an action when the monitor is started for the first time (e.g., configuration).
        """
        pass

    def close(self):
        """
        Performs an action when the monitor is closed or destroyed.
        """
        pass

    def start(self):
        """
        Starts the monitor processing.
        """
        if not self.__setup_done:
            self.setup()
        self._processing = True

    def stop(self):
        """
        Stops the monitor processing.
        """
        self._processing = False

    def process_packet(self, packet):
        """
        Performs the monitoring action when a packet is received or transmitted by the targeted connector.

        :param packet: scapy packet to process
        """
        pass

    def __del__(self):
        self.close()

from .pcap import PcapWriterMonitor
from .wireshark import WiresharkMonitor
