"""
ANT Scanner connector
=====================
"""
import logging
from time import time
from typing import Generator, Iterator, Optional

from scapy.packet import Packet

from whad.exceptions import UnsupportedCapability, WhadDeviceNotReady

from .sniffer import Sniffer
from ..scanning import ANTDevicesDB, ANTDiscoveredDevice
from ..sniffing import SnifferConfiguration
from ..crypto import ANT_PLUS_NETWORK_KEY


logger = logging.getLogger(__name__)


class Scanner(Sniffer):
    """
    ANT Scanner interface for compatible WHAD device.

    This connector uses the ANT sniffing feature to listen for incoming ANT
    broadcasts and extracts device identifiers from each received PDU to
    populate a device database.

    A typical use is shown below:

    .. code-block:: python

        with Scanner(device) as scanner:
            for device in scanner.discover_devices():
                print(device)
    """

    def __init__(self, device):
        """Instantiate scanner connector over ``device``.

        :param  device:        ANT WHAD device instance.
        :type   device:        :class:`whad.device.WhadDevice`
        """
        configuration = SnifferConfiguration(
            channel = 57, 
            network_key = ANT_PLUS_NETWORK_KEY, 
            transmission_type = 0, 
            device_type = 0, 
            device_number = 0
        )

        # Initialize the parent connectors.
        super().__init__(device)
        self.configuration = configuration
        self.started = False
        # Device database.
        self.__db = ANTDevicesDB()

    def start(self) -> bool:
        """Start the ANT scanner.

        Calling this method resets the discovered devices database and starts
        the underlying sniffer.
        """
        if super().start():
            self.started = True
            self.__db.reset()
            return True
        return False
    def stop(self) -> bool:
        """Stop the ANT scanner.

        Stops the underlying sniffer.
        """
        if super().stop():
            self.started = False
            return True
        return False

    def __enter__(self) -> "Scanner":
        """Use this connector as a context manager.
        """
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Close the connector when used as a context manager.
        """
        if self.started:
            if not self.stop():
                raise WhadDeviceNotReady()

    def clear(self):
        """Clear the device database.
        """
        self.__db.reset()

    def discover_devices(
            self,
            device_type: Optional[int] = None,
            device_number: Optional[int] = None,
            transmission_type: Optional[int] = None,
            timeout: Optional[float] = None,
            updates: bool = False,
    ) -> Iterator[ANTDiscoveredDevice]:
        """Discover ANT devices broadcasting on the monitored channel.

        :param  device_type:        Filter on a specific device type.
        :type   device_type:        int, optional
        :param  device_number:      Filter on a specific device number.
        :type   device_number:      int, optional
        :param  transmission_type:  Filter on a specific transmission type.
        :type   transmission_type:  int, optional
        :param  timeout:            Timeout in seconds.
        :type   timeout:            float, optional
        :param  updates:            If set to ``True``, already known devices
                                    whose state has been updated are also
                                    yielded.
        :type   updates:            bool
        """
        # Make sure the sniffer is running.
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
            stop_on_exit = True
        else:
            stop_on_exit = False
        
        try:
            start_time = time()
            for packet in self.sniff():
                # Apply optional filters before updating the database.
                if device_type is not None and getattr(packet, "device_type", None) != device_type:
                    continue
                if device_number is not None and getattr(packet, "device_number", None) != device_number:
                    continue
                if transmission_type is not None and getattr(packet, "transmission_type", None) != transmission_type:
                    continue

                devices = self.__db.on_device_found(
                    packet,
                    filter_device_type=device_type,
                    filter_device_number=device_number,
                    filter_transmission_type=transmission_type,
                    updates=updates
                )

                for dev in devices:
                    yield dev

                if timeout is not None and (time() - start_time) >= timeout:
                    break
        finally:
            if stop_on_exit:
                self.stop()