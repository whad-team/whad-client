from whad.device import WhadDeviceConnector

class WhadMonitor:
    def __init__(self, monitor_reception=True, monitor_transmission=True):
        self._connector = None
        self.__monitor_reception = monitor_reception
        self.__monitor_transmission = monitor_transmission
        self.__setup_done = False
        self._processing = False

    def attach(self, connector):
        success = False
        if isinstance(connector, WhadDeviceConnector):
            self._connector = connector
            if self.__monitor_reception:
                self._connector.attach_callback(self.process_packet, on_reception = True)
                print("[i] reception callback attached.")
                success = True

            if self.__monitor_transmission:
                self._connector.attach_callback(self.process_packet, on_transmission = True)
                print("[i] transmission callback attached.")
                success = True
        return success

    def detach(self):
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
        pass

    def close(self):
        pass

    def start(self):
        if not self.__setup_done:
            self.setup()
        self._processing = True

    def stop(self):
        self._processing = False

    def process_packet(self, packet):
        pass

    def __del__(self):
        self.close()

from .pcap import PcapWriterMonitor
