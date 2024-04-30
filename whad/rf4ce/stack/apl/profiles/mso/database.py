from whad.rf4ce.stack.apl.profiles.mso.parsers import PeripheralIDsValue,\
    VersioningValue, BatteryStatusValue, ValidationConfigurationValue
from struct import pack

class InformationAttribute:
    def __init__(self, name, identifier, value, writable=False):
        self.name = name
        self.identifier = identifier
        self.writable = writable
        self.value = value


class InformationBase:
    def __init__(self):
        self.attributes = [
            InformationAttribute(
                name="Peripheral IDs",
                identifier=0x00,
                value=PeripheralIDsValue.pack([]),
                writable=True
            ),
            InformationAttribute(
                name="RF Statistics",
                identifier=0x01,
                value=b"\x00"*16,
                writable=True
            ),
            InformationAttribute(
                name="Versioning",
                identifier=0x02,
                value=VersioningValue.pack(
                    (1, 0, 0, 0),
                    (1, 0, 0, 0),
                    (1, 0, 0, 0),
                ),
                writable=True
            ),
            InformationAttribute(
                name="Battery Status",
                identifier=0x03,
                value=BatteryStatusValue.pack(
                    (False, False, False),
                    4.0,
                    0,
                    0,
                    4.0
                ),
                writable=True
            ),
            InformationAttribute(
                name="Short RF Retry Period",
                identifier=0x04,
                value=pack("I", 100000),
                writable=False
            ),
            InformationAttribute(
                name="IR-RF Database",
                identifier=0xDB,
                value=b"",
                writable=False
            ),
            InformationAttribute(
                name="Validation Configuration",
                identifier=0xDC,
                value=ValidationConfigurationValue.pack(61680,61680),
                writable=False
            ),
            InformationAttribute(
                name="General Purpose",
                identifier=0xFF,
                value = b"\x00" * 16 * 32,
                writable=True
            ),
        ]

    def get(self, filter = lambda _ : True):
        for attribute in self.attributes:
            if filter(attribute):
                return attribute
        return None

    def set(self, filter = lambda _ : True, value=b""):
        for attribute in self.attributes:
            if filter(attribute):
                attribute.value = value
                return attribute
        return None
