"""Bluetooth GAP Advertisement data
"""
from struct import pack, unpack
from whad.domain.ble.profile.attribute import UUID

class AdvDataError(Exception):
    def __init__(self):
        super().__init__()

class AdvDataFieldListOverflow(Exception):
    def __init__(self):
        super().__init__()

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

class AdvUuid16List(AdvDataField):
    """16-bit UUID list.
    """

    def __init__(self, eir_tag, *args):
        """Create a list of 16-bit UUID.
        """
        # First, make sure all arguments are 16-bit UUID objects
        self.__uuids = []
        for arg in args:
            if not isinstance(arg, UUID):
                raise ValueError
            elif arg.type != UUID.TYPE_16:
                raise ValueError
            else:
                self.__uuids.append(arg)

        # Pack data
        super().__init__(eir_tag, b''.join([uuid.packed for uuid in self.__uuids]))

    def __len__(self):
        return len(self.__uuids)

    def __getitem__(self, index):
        if index >= 0 and index < len(self.__uuids):
            return self.__uuids[index]
        else:
            raise IndexError

    @staticmethod
    def from_bytes(clazz, ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        nb_uuids = int(len(ad_record)/2)
        uuids = []
        for i in range(nb_uuids):
            uuids.append(UUID(ad_record[i*2:(i+1)*2]))
        return clazz(*uuids)

class AdvUuid128List(AdvDataField):
    """128-bit UUID list.
    """

    def __init__(self, eir_tag, *args):
        """Create a list of 128-bit UUID.
        """
        # First, make sure all arguments are 128-bit UUID objects
        self.__uuids = []
        for arg in args:
            if not isinstance(arg, UUID):
                raise ValueError
            elif arg.type != UUID.TYPE_128:
                raise ValueError
            else:
                self.__uuids.append(arg)

        # Pack data
        super().__init__(eir_tag, b''.join([uuid.packed for uuid in self.__uuids]))

    def __len__(self):
        return len(self.__uuids)

    def __getitem__(self, index):
        if index >= 0 and index < len(self.__uuids):
            return self.__uuids[index]
        else:
            raise IndexError

    @staticmethod
    def from_bytes(clazz, ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        nb_uuids = int(len(ad_record)/16)
        uuids = []
        for i in range(nb_uuids):
            uuids.append(UUID(ad_record[i*16:(i+1)*16]))
        return clazz(*uuids)


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

    @staticmethod
    def from_bytes(ad_record):
        """Convert an AD record into an AdvFlagsField object.
        """

        if len(ad_record) > 1:
            raise AdvDataError
        else:
            limited_disc = ((ad_record[0] & 0x01) != 0)
            general_disc = ((ad_record[0] & 0x02) != 0)
            bredr_support = ((ad_record[0] & 0x04) != 0)
            lebredr_support = ((ad_record[0] & 0x08) != 0)
            return AdvFlagsField(
                limited_disc=limited_disc,
                general_disc=general_disc,
                bredr_support=bredr_support,
                le_bredr_support=lebredr_support
            )

class AdvShortenedLocalName(AdvDataField):
    """Device shortened local name
    """

    def __init__(self, local_name):
        super().__init__(0x08, local_name)

    @staticmethod
    def from_bytes(ad_record):
        return AdvShortenedLocalName(ad_record)

class AdvCompleteLocalName(AdvDataField):
    """Device complete local name
    """

    def __init__(self, local_name):
        super().__init__(0x09, local_name)

    @staticmethod
    def from_bytes(ad_record):
        return AdvCompleteLocalName(ad_record)

class AdvTxPowerLevel(AdvDataField):
    """Device Tx power level
    """

    def __init__(self, level):
        super().__init__(0x0A, bytes([level&0xff]))

    @staticmethod
    def from_bytes(ad_record):
        return AdvTxPowerLevel(ad_record[0])


class AdvManufacturerSpecificData(AdvDataField):
    """Device Manufacturer Specific Data
    """

    def __init__(self, company_id, data):
        super().__init__(0xFF, pack('<H', company_id&0xffff) + bytes(data))

    @staticmethod
    def from_bytes(ad_record):
        if len(ad_record) >= 2:
            return AdvManufacturerSpecificData(
                unpack('<H', ad_record[:2])[0],
                ad_record[2:]
            )
        else:
            raise AdvDataError


class AdvIncServiceUuid16List(AdvDataField):
    """Incomplete Service 16-bit UUID list.
    """

    def __init__(self, *args):
        super().__init__(0x02, *args)

    @staticmethod
    def from_bytes(ad_record):
        return AdvUuid16List.from_bytes(AdvIncServiceUuid16List, ad_record)


class AdvCompServiceUuid16List(AdvUuid16List):

    def __init__(self, *args):
        super().__init__(0x03, *args)

    @staticmethod
    def from_bytes(ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        return AdvUuid16List.from_bytes(AdvCompServiceUuid16List, ad_record)

class AdvIncServiceUuid128List(AdvUuid128List):

    def __init__(self, *args):
        super().__init__(0x06, *args)

    @staticmethod
    def from_bytes(ad_record):
        return AdvUuid128List.from_bytes(AdvIncServiceUuid128List, ad_record)

class AdvCompServiceUuid128List(AdvUuid128List):

    def __init__(self, *args):
        """Create a list of 128-bit UUID.
        """
        super().__init__(0x07, *args)

    @staticmethod
    def from_bytes(ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        return AdvUuid128List.from_bytes(AdvCompServiceUuid128List, ad_record)


class AdvDataFieldList(object):
    """Advertisement field list
    """

    EIR_HANDLERS = {
        0x01: AdvFlagsField,
        0x02: AdvIncServiceUuid16List,
        0x03: AdvCompServiceUuid16List,
        #0x04: AdvIncServiceUUID32List,
        #0x05: AdvCompServiceUUID32List,
        0x06: AdvIncServiceUuid128List,
        0x07: AdvCompServiceUuid128List,
        0x08: AdvShortenedLocalName,
        0x09: AdvCompleteLocalName,
        0x0A: AdvTxPowerLevel,
        #0x0D: AdvDeviceClass,
        #0x10: AdvDeviceId,
        #0x12: AdvSlaveConnIntervalRange,
        #0x14: AdvServiceSollicitationUuid16List,
        #0x15: AdvServiceSollicitationUuid128List,
        #0x16: AdvServiceData,
        #0x17: AdvPublicTargetAddr,
        #0x18: AdvRandomTargetAddr,
        #0x19: AdvAppearance,
        #0x1A: AdvAdvertisingInterval,
        #0x1B: AdvBluetoothDeviceAddr,
        #0x1C: AdvLeRole,
        #0x1F: AdvServiceSollicitationUuid32List,
        #0x20: AdvServiceDataUuid32,
        #0x21: AdvServiceDataUuid128,
        #0x24: AdvURI,
        #0x25: AdvIndoorPositioning,
        #0x26: AdvTransportDiscData,
        #0x27: AdvLeSupportedFeatures,
        #0x28: AdvChannelMapUpdateIndication,
        #0x29: AdvPbAdv,
        #0x2A: AdvMeshMessage,
        #0x2B: AdvMeshBeacon,
        #0x2C: AdvBigInfo,
        #0x2D: AdvBroadcastCode,
        #0x2F: AdvAdvertisingIntervalLong,
        #0x30: AdvBroadcastName,
        #0x3D: Adv3dInfoData,
        0xFF: AdvManufacturerSpecificData
    }


    def __init__(self, *args):
        self.__fields = []
        for field in args:
            self.add(field)

    def __len__(self):
        return len(self.__fields)

    def __getitem__(self, index):
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
            
    @staticmethod
    def from_bytes(adv_data):
        """Convert raw advertising data into an AdvDataFieldList object.

        :param bytes adv_data: Raw advertising data
        :rtype: AdvDataFieldList
        :returns: Instance of AdvDataFieldList populated with records
        """
        if len(adv_data) > 31:
            raise AdvDataFieldListOverflow
        else:
            adv_list = AdvDataFieldList()
            while len(adv_data) >= 2:
                # Unpack length and eir_tag
                length, eir_tag = unpack('<BB', adv_data[:2])

                # Check length
                if len(adv_data[2:]) >= (length - 1):
                    # Extract EIR data
                    eir_payload = adv_data[2:2 + length - 1]

                    # Add record based on EIR tag
                    if eir_tag in AdvDataFieldList.EIR_HANDLERS:
                        adv_list.add(
                            AdvDataFieldList.EIR_HANDLERS[eir_tag].from_bytes(eir_payload)
                        )
                    adv_data = adv_data[length+1:]
                else:
                    raise AdvDataError
            return adv_list
