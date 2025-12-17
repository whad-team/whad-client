"""GAP Heart Rate Service

This module provides an implementation of a standard Heart Rate service as defined in
the specification. This implementation supports the following features:
- Heart rate value update
- Energy expended update
- Skin contact depending on the configuration (default: no sensor supported)

The :class:`whad.ble.profile.services.hr.HeartRateService` class sends a specific
:class:`whad.ble.profile.services.hr.HeartRateService.UpdateEvent` event to registered
event handlers when used in a GATT client. This event allows a client application
to get updates as they are sent by the remote heart rate monitoring device.
"""
from struct import pack, unpack
from typing import Optional

from whad.ble.profile.attribute import UUID
from whad.ble.profile.device import PeripheralCharacteristic
from whad.ble.profile.service import StandardService, ServiceEvent
from whad.ble.profile.characteristic import Characteristic

class HeartRateService(StandardService):
    """Heart Rate service version 1.0 as defined in
    `specification <https://www.bluetooth.com/specifications/specs/html/?src=HRS_v1.0/out/en/index-en.html>`_.
    """

    class UpdateEvent(ServiceEvent):
        """Heart Rate service update event."""

        def __init__(self, rate: int, energy_expended: Optional[int], skin_contact: Optional[bool]):
            """Initialize an update event.

            :param rate: Heart rate value, in BPM
            :type  rate: int
            :param energy_expended: Energy expended, in kJ
            :type  energy_expended: int, optional
            :param skin_contact: Skin contact detected
            :type  skin_contact: bool, optional
            """
            self.__rate = rate
            self.__energy_expended = energy_expended
            self.__skin_contact = skin_contact

        @property
        def heart_rate(self) -> int:
            """Heart Rate value"""
            return self.__rate

        @property
        def energy_expended(self) -> Optional[int]:
            """Energy expended, if available."""
            return self.__energy_expended

        @property
        def skin_contact(self) -> Optional[bool]:
            """Skin contact detected, if sensor is present."""
            return self.__skin_contact

    # Service UUID
    _uuid = UUID(0x180d)

    # Flags
    FLAG_VALUE_FORMAT = 0x01
    FLAG_SENSOR_CONTACT = 0x02
    FLAG_SKIN_CONTACT = 0x04
    FLAG_ENERGY_EXP = 0x08
    FLAG_RR_INTERVAL = 0x10

    # Value format
    FORMAT_8BIT = 0
    FORMAT_16BIT = 1

    measurement = Characteristic(
        UUID(0x2a37),
        properties=Characteristic.NOTIFY,
        required=True,
        value=b''
    )

    body_sensor_location = Characteristic(
        UUID(0x2a38),
        properties=Characteristic.READ,
        value=b'Chest'
    )

    def __init__(self, handle: int = 0, end_handle: int = 0):
        """Initialize our heart rate service.

        :param handle: Service start handle
        :type  handle: int, optional
        :param end_handle: Service end handle
        :type  handle: int, optional
        :param contact: Enable sensor contact support
        :type  contact: bool
        """
        # Save information flags
        self.__contact = False
        self.__skin = False
        self.__heart_rate = 0
        self.__energy_expended = None

        # Initizalize this standard service
        super().__init__(handle=handle, end_handle=end_handle)

        # Subscribe for notifications if characteristic is of type `PeripheralCharacteristic`
        # (it means this service has been instantiated in a PeripheralProfile class and that
        # we act as a GATT client)
        if isinstance(self.measurement, PeripheralCharacteristic):
            self.measurement.subscribe(notification=True, callback=self.on_update)

    @property
    def location(self) -> str:
        return self.body_sensor_location.value.decode('utf-8')

    @property
    def rate(self) -> int:
        """Heart rate in BPM."""
        return self.__heart_rate

    @property
    def skin_contact(self) -> bool:
        """Skin contact status"""
        return self.__skin

    @property
    def energy_expended(self) -> Optional[int]:
        """Energy expended in kJ"""
        return self.__energy_expended

    @property
    def contact_sensor(self) -> bool:
        """Contact sensor present"""
        return self.__contact

    def enable_contact(self, contact: bool):
        """Enable/disable contact support."""
        self.__contact = contact

    def set_location(self, location: str):
        """Update body sensor location's characteristic value.

        :param location: Sensor location
        :type  location: str
        """
        self.body_sensor_location.value = location.encode('utf-8')

    def on_update(self, _: Characteristic, value: bytes, __: bool = False):
        """Process incoming notifications."""
        # We should at least get two bytes
        if len(value) < 2:
            raise ValueError()

        # Retrieve flags
        flags = value[0]
        offset = 1

        # Fetch contact and skin contact bits
        if (flags & self.FLAG_SENSOR_CONTACT) > 0:
            self.__contact = True
            if (flags & self.FLAG_SKIN_CONTACT) > 0:
                self.__skin = True
            else:
                self.__skin = False
        else:
            self.__contact = False
            self.__skin = False

        # Fetch heart rate value
        if (flags & self.FLAG_VALUE_FORMAT) > 0:
            # Check size
            if len(value) < 3:
                raise ValueError()
            # Parse
            self.__heart_rate = unpack('<H', value[1:3])[0]
            offset += 2
        else:
            self.__heart_rate = unpack('<B', value[1:2])[0]
            offset += 1

        # Fetch energy expended value if present
        if (flags & self.FLAG_ENERGY_EXP) > 0:
            # Check size
            if len(value) < (offset + 2):
                raise ValueError()
            # Parse value
            self.__energy_expended = unpack('<H', value[offset:offset+2])[0]
        else:
            self.__energy_expended = None

        # Send update event
        self.send_event(HeartRateService.UpdateEvent(
            self.__heart_rate,
            self.__energy_expended,
            self.__skin
        ))

    def update(self, rate: int, energy: Optional[int] = None, skin: Optional[bool] = None):
        """Update the measurement characteristic with the corresponding values.

        :param rate: Current heart rate in BPM
        :type  rate: int
        :param energy: Energy expended in kJ
        :type  energy: int, optional
        :param skin: Skin contact
        :type  skin: bool, optional
        """
        # Check heart rate value
        if rate < 0 or rate > 0xffff:
            raise ValueError()
        self.__heart_rate = rate

        # Build flags
        flags = 0
        if rate > 255:
            flags |= self.FLAG_VALUE_FORMAT

        # Check expended energy value and set flags
        if energy is not None:
            if energy < 0:
                raise ValueError()
            if energy > 0xffff:
                energy = 0xffff
            flags |= self.FLAG_ENERGY_EXP
            self.__energy_expended = energy

        # Check skin contact
        self.__contact = False
        if skin is not None and self.__contact:
            flags |= self.FLAG_SENSOR_CONTACT
            self.__contact = True
            if skin:
                flags |= self.FLAG_SKIN_CONTACT
                self.__skin = True
            else:
                self.__skin = False

        # Generate measure value
        value = b''
        if rate < 256:
            value += pack('<B', rate)
        else:
            value += pack('<H', rate)

        # Include expended energy if required
        if energy is not None:
            value += pack('<H', energy)

        # Update our measurement characteristic
        self.measurement.value = bytes([flags]) + value

