"""
ANT Scanning device database

This module provides a database that keeps track of ANT devices discovered
through the scanning process, :class:`whad.ant.scanning.ANTDevicesDB`.

An ANT device is identified by the triplet ``(device_number, device_type,
transmission_type)`` along with the RF channel on which it has been observed.
"""
from time import time
from typing import Optional, List

from whad.scapy.layers.ant import ANT_Hdr, ANT_PLUS_PROFILES


class ANTDiscoveredDevice:
    """Store information about a discovered ANT device:

    * Received Signal Strength Indicator (RSSI)
    * Device number
    * Device type
    * Transmission type
    * Set of RF channels on which the device has been observed
    * Optional profile (e.g. ANT+ profile) inferred from the device type
    * Last payload received from the device
    """

    def __init__(self, rssi, device_number, device_type, transmission_type,
                 rf_channel=None, payload=None, timestamp=None):
        """Instantiate an ANTDiscoveredDevice.

        :param  rssi:               Received Signal Strength Indicator
        :type   rssi:               int
        :param  device_number:      ANT device number
        :type   device_number:      int
        :param  device_type:        ANT device type
        :type   device_type:        int
        :param  transmission_type:  ANT transmission type
        :type   transmission_type:  int
        :param  rf_channel:         RF channel on which the device has been seen
        :type   rf_channel:         int, optional
        :param  payload:            Last payload received from this device
        :type   payload:            bytes, optional
        :param  timestamp:          Timestamp of the discovery
        :type   timestamp:          float, optional
        """
        self.__device_number = device_number
        self.__device_type = device_type
        self.__transmission_type = transmission_type
        self.__rssi = rssi
        self.__channels = [rf_channel] if rf_channel is not None else []
        self.__payload = payload
        self.__timestamp = timestamp if timestamp is not None else time()
        self.__last_seen = self.__timestamp

    @property
    def device_number(self) -> int:
        """Device number.
        """
        return self.__device_number

    @property
    def device_type(self) -> int:
        """Device type.
        """
        return self.__device_type

    @property
    def transmission_type(self) -> int:
        """Transmission type.
        """
        return self.__transmission_type

    @property
    def rssi(self) -> int:
        """Device RSSI.
        """
        return self.__rssi

    @property
    def channels(self) -> List[int]:
        """Channels used by the device.

        :return: list of channels used by the device, in ascending order
        :rtype: list
        """
        channels = list(set(self.__channels))
        channels.sort()
        return channels

    @property
    def last_channel(self) -> int:
        """Last channel used by the device.
        """
        if len(self.__channels) == 0:
            return None
        return self.__channels[-1]

    @property
    def payload(self) -> bytes:
        """Last payload received from this device.
        """
        return self.__payload

    @property
    def timestamp(self) -> float:
        """Device discovery timestamp.
        """
        return self.__timestamp

    @property
    def last_seen(self) -> float:
        """Device last seen timestamp.
        """
        return self.__last_seen

    @property
    def profile(self) -> Optional[str]:
        """Inferred applicative profile name, based on the device type.

        :return: profile name if known, ``None`` otherwise.
        :rtype: str, optional
        """
        if self.__device_type in ANT_PLUS_PROFILES:
            profile = ANT_PLUS_PROFILES[self.__device_type]
            return profile.profile_name if hasattr(profile, "profile_name") else str(profile)
        return None

    def __eq__(self, other):
        """Two devices are considered equal if they share the same
        ``(device_number, device_type, transmission_type)`` triplet.
        """
        return (
            self.__device_number == other.device_number and
            self.__device_type == other.device_type and
            self.__transmission_type == other.transmission_type
        )

    def __hash__(self):
        return hash((self.__device_number, self.__device_type, self.__transmission_type))

    def __repr__(self):
        """Show device information.
        """
        profile_info = f" ({self.profile})" if self.profile is not None else ""
        channels_list = ", ".join([str(c) for c in self.channels])
        channels = (
            f"channels=[{channels_list}]" if channels_list
            else "channels=[]"
        )
        rssi_str = f"[{self.__rssi:4d} dBm] " if self.__rssi is not None else ""
        return (
            f"{rssi_str} "
            f"device_number={self.__device_number} "
            f"device_type={self.__device_type}{profile_info} "
            f"transmission_type={self.__transmission_type} "
            f"{channels}"
        )

    def seen(self):
        """Mark device as seen (update last_seen value with current time).
        """
        self.__last_seen = time()

    def update_rssi(self, rssi: int):
        """Update device RSSI.

        :param  rssi: New RSSI value.
        :type   rssi: int
        """
        self.__rssi = rssi

    def update_channel(self, rf_channel: int):
        """Update device channels in use.

        :param  rf_channel: New RF channel value.
        :type   rf_channel: int
        """
        self.__channels.append(rf_channel)

    def update_payload(self, payload: bytes):
        """Update the last payload received from this device.

        :param  payload: New payload value.
        :type   payload: bytes
        """
        self.__payload = payload


class ANTDevicesDB:
    """ANT devices database.

    This class stores information about ANT devices discovered during a
    scanning session. A device is uniquely identified by the
    ``(device_number, device_type, transmission_type)`` triplet.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Remove database content.
        """
        self.__db = {}

    def find_device(self, device_number, device_type, transmission_type) -> ANTDiscoveredDevice:
        """Find a device based on its identifiers.

        :param      device_number:     ANT device number
        :type       device_number:     int
        :param      device_type:       ANT device type
        :type       device_type:       int
        :param      transmission_type: ANT transmission type
        :type       transmission_type: int
        :return:    Device if found, ``None`` otherwise.
        :rtype:     :class:`whad.ant.scanning.ANTDiscoveredDevice`
        """
        key = (device_number, device_type, transmission_type)
        return self.__db.get(key, None)

    def register_device(self, device: ANTDiscoveredDevice):
        """Register or update a device.

        :param device: Device to register
        :type device: :class:`whad.ant.scanning.ANTDiscoveredDevice`
        """
        key = (device.device_number, device.device_type, device.transmission_type)
        self.__db[key] = device

    def update_device(self, device: ANTDiscoveredDevice, rssi: int = None,
                      rf_channel: int = None, payload: bytes = None):
        """Update a known device.

        :param device: Device to update
        :type device: :class:`whad.ant.scanning.ANTDiscoveredDevice`
        :param rssi: New RSSI value
        :type rssi: int, optional
        :param rf_channel: New RF channel value
        :type rf_channel: int, optional
        :param payload: New payload
        :type payload: bytes, optional
        """
        device.seen()
        if rssi is not None:
            device.update_rssi(rssi)
        if rf_channel is not None:
            device.update_channel(rf_channel)
        if payload is not None:
            device.update_payload(payload)

    def on_device_found(self, packet, rssi: int = None,
                        filter_device_number: int = None,
                        filter_device_type: int = None,
                        filter_transmission_type: int = None,
                        updates: bool = False):
        """Handle a packet received from a device.

        Parse the incoming packet, extract the device identifiers and register
        or update the corresponding device in the database.

        :param  packet:                    Packet that has been received
        :type   packet:                    :class:`scapy.packet.Packet`
        :param  rssi:                      Received Signal Strength Indicator
        :type   rssi:                      int, optional
        :param  filter_device_number:      Device number to filter
        :type   filter_device_number:      int, optional
        :param  filter_device_type:        Device type to filter
        :type   filter_device_type:        int, optional
        :param  filter_transmission_type:  Transmission type to filter
        :type   filter_transmission_type:  int, optional
        :param  updates:                   If set to ``True``, return devices
                                           whose state has been updated.
        :type   updates:                   bool
        :return: A list of devices (newly discovered or updated depending on
                 ``updates``).
        :rtype: list
        """
        if not isinstance(packet, ANT_Hdr):
            return []

        device_number = packet.device_number
        device_type = packet.device_type
        transmission_type = packet.transmission_type

        # If the device identifiers are not available, ignore the packet.
        if device_number is None or device_type is None or transmission_type is None:
            return []

        # Apply filters, if any.
        if filter_device_number is not None and device_number != filter_device_number:
            return []
        if filter_device_type is not None and device_type != filter_device_type:
            return []
        if filter_transmission_type is not None and transmission_type != filter_transmission_type:
            return []

        # Extract the metadata (RF channel, RSSI).
        rf_channel = None
        if hasattr(packet, "metadata") and packet.metadata is not None:
            if getattr(packet.metadata, "rf_channel", None) is not None:
                rf_channel = packet.metadata.rf_channel
            if rssi is None and getattr(packet.metadata, "rssi", None) is not None:
                rssi = packet.metadata.rssi

        # Extract the payload (everything below ANT_Hdr).
        payload = bytes(packet[ANT_Hdr:]) if ANT_Hdr in packet else None

        # Have we already discovered this device?
        existing_device = self.find_device(device_number, device_type, transmission_type)
        if existing_device is None:
            new_device = ANTDiscoveredDevice(
                rssi=rssi,
                device_number=device_number,
                device_type=device_type,
                transmission_type=transmission_type,
                rf_channel=rf_channel,
                payload=payload,
            )
            self.register_device(new_device)
            return [new_device]

        # Existing device, update it.
        self.update_device(existing_device, rssi=rssi, rf_channel=rf_channel,
                           payload=payload)
        if updates:
            return [existing_device]
        return []
