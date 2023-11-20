"""Bluetooth Low Energy Device Information Service Profile
"""
from struct import pack, unpack
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic

class DeviceInformationService(object):
    """Define Device Information Service
    """

    device_info = PrimaryService(
        uuid=UUID(0x180a),
        manufacturer=Characteristic(
            uuid=UUID(0x2A29),
            permissions=['read'],
        ),
        model_number=Characteristic(
            uuid=UUID(0x2A24),
            permissions=['read']
        ),
        serial_number=Characteristic(
            uuid=UUID(0x2A25),
            permissions=['read']
        ),
        hw_revision=Characteristic(
            uuid=UUID(0x2A27),
            permissions=['read']
        ),
        fw_revision=Characteristic(
            uuid=UUID(0x2A26),
            permissions=['read']
        ),
        sw_revision=Characteristic(
            uuid=UUID(0x2A28),
            permissions=['read']
        ),
        system_id=Characteristic(
            uuid=UUID(0x2A23),
            permissions=['read']
        ),
        ieee_rcdl=Characteristic(
            uuid=UUID(0x2A2A),
            permissions=['read']
        ),
        pnp_id=Characteristic(
            uuid=UUID(0x2A50),
            permissions=['read']
        )
    )

    @property
    def manufacturer(self):
        """Read device manufacturer
        """
        return self.device_info.manufacturer.value

    @manufacturer.setter
    def manufacturer(self, manufacturer: bytes):
        """Set device manufacturer name
        """
        self.device_info.manufacturer_name.value = manufacturer

    @property
    def model(self):
        """Read model number
        """
        return self.device_info.model_number.value

    @model.setter
    def model(self, model_number: bytes):
        self.device_info.model_number.value = model_number

    @property
    def serial(self):
        """Read device serial number
        """
        return self.device_info.serial_number.value

    @serial.setter
    def serial(self, serial_number: bytes):
        """Set device serial number
        """
        self.device_info.serial_number.value = serial_number

    @property
    def hw_revision(self):
        """Return current hw revision string
        """
        return self.device_info.hw_revision.value

    @hw_revision.setter
    def hw_revision(self, hw_revision_value: bytes):
        """Set device HW revision string
        """
        self.device_info.hw_revision.value = hw_revision_value

    @property
    def fw_revision(self):
        """Return current fw_revision string
        """
        return self.device_info.fw_revision.value

    @fw_revision.setter
    def fw_revision(self, fw_revision_value: bytes):
        """Set fw revision
        """
        self.device_info.fw_revision.value = fw_revision_value

    @property
    def sw_revision(self):
        """Return current sw_revision string
        """
        return self.device_info.sw_revision.value

    @sw_revision.setter
    def sw_revision(self, sw_revision_value: bytes):
        """Set fw revision
        """
        self.device_info.sw_revision.value = sw_revision_value

    @property
    def system_id(self):
        """Return system id
        """
        return self.device_info.system_id.value

    @system_id.setter
    def system_id(self, sysid_value: bytes):
        """Set system ID
        """
        self.device_info.system_id.value = sysid_value