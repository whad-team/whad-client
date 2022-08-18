"""Bluetooth GAP Advertisement data
"""
from struct import pack

class AdvDataFieldListOverflow(Exception):
    def __init__(self):
        super().__init__(self)

class AdvDataField(object):
    """Advertisement basic data field
    """

    def __init__(self, adv_type, value=b''):
        self.__type = adv_type
        self.__value = value

    @property
    def type(self):
        return self.__type

    def to_bytes(self):
        return pack('<BB', len(self.__value) + 1, self.__type) + self.__value

class AdvFlagsField(AdvDataField):
    """Advertisement Flags Data field

    This advertisement field specifies the device capabilities.
    """

    def __init__(self, limited_disc=False, general_disc=True, bredr_support=True, le_bredr_support=False):
        """
        :param bool limited_disc: If set, enable the limited discoverable mode
        :param bool general_disc: If set, enable the generic discoverable mode
        :param bool bredr_support: If set, advertise the device does not support BR/EDR mode
        :param bool le_bredr_support: If set, advertise LE and BR/EDR support
        """
        flags = 0x00
        if limited_disc:
            flags |= 0x01
        if general_disc:
            flags |= 0x02
        if bredr_support:
            flags |= 0x04
        if le_bredr_support:
            flags |= 0x08
        super().__init__(0x01, bytes([flags]))

class AdvShortenedLocalName(AdvDataField):
    """Device shortened local name
    """

    def __init__(self, local_name):
        super().__init__(0x08, local_name)

class AdvCompleteLocalName(AdvDataField):
    """Device complete local name
    """

    def __init__(self, local_name):
        super().__init__(0x09, local_name)

class AdvTxPowerLevel(AdvDataField):
    """Device Tx power level
    """

    def __init__(self, level):
        super().__init__(0x0A, bytes([level&0xff]))

class AdvManufacturerSpecificData(AdvDataField):
    """Device Manufacturer Specific Data
    """

    def __init__(self, company_id, data):
        super().__init__(0xFF, pack('<H', company_id&0xffff) + bytes(data))

class AdvDataFieldList(object):
    """Advertisement field list
    """

    def __init__(self, *args):
        self.__fields = []
        for field in args:
            self.add(field)

    def __len__(self):
        return len(self.__fields)

    def __get__(self, index):
        if index>=0 and index<len(self.__fields):
            return self.__fields[index]
        else:
            raise IndexError

    def add(self, item):
        if isinstance(item, AdvDataField):
            self.__fields.append(item)
        else:
            raise AttributeError

    def to_bytes(self):
        """Convert field list to bytes
        """
        output = b''
        for field in self.__fields:
            field_record = field.to_bytes()
            if len(output) + len(field_record) <= 31:
                output += field_record
            else:
                raise AdvDataFieldListOverflow
        return output
            