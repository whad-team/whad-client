"""Bluetooth GAP Advertisement data
"""
from struct import pack, unpack
from urllib.parse import urlparse
from whad.ble import BDAddress
from whad.ble.profile.attribute import UUID


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
        self.__name = local_name
        super().__init__(0x08, local_name)

    @property
    def name(self):
        return self.__name

    @staticmethod
    def from_bytes(ad_record):
        return AdvShortenedLocalName(ad_record)

class AdvCompleteLocalName(AdvDataField):
    """Device complete local name
    """

    def __init__(self, local_name):
        self.__name = local_name
        super().__init__(0x09, local_name)

    @property
    def name(self):
        return self.__name

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
        if len(ad_record) >= 1:
            return AdvTxPowerLevel(ad_record[0])
        else:
            raise AdvDataError


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

class AdvSlaveConnIntervalRange(AdvDataField):
    """Advertising data Slave Connection Interval Range
    """

    def __init__(self, min_value=0xFFFF, max_value=0xFFFF):
        """Create a Slave Connection Interval Range advertising data record.

        :param int min_value: Min interval range (0x0006 - 0x0C80)
        :param int max_value: Max interval range (0x0006 - 0x0C80)
        """
        self.__range = [min_value, max_value]
        super().__init__(0x12, pack('<HH', min_value, max_value))

    @property
    def range(self):
        return self.__range

    @property
    def min(self):
        return self.__range[0]

    @property
    def max(self):
        return self.__range[1]

    @staticmethod
    def from_bytes(adv_record):
        """Create an AdvSlaveConnIntervalRange from serialized bytes.

        :param bytes adv_record: Serialized Advertisement Data Record to parse.
        :rtype: AdvSlaveConnIntervalRange
        :returns: Returns an instance of :class:`AdvSlaveConnIntervalRange`.
        """
        if len(adv_record) == 4:
            min_value, max_value = unpack('<HH', adv_record)
            return AdvSlaveConnIntervalRange(min_value, max_value)
        else:
            raise AdvDataError

class AdvServiceSollicitationUuid16List(AdvUuid16List):
    """List of 16-bit Service sollicitation UUIDs.
    """

    def __init__(self, *args):
        """Create a list of 16-bit UUID.
        """
        super().__init__(0x14, *args)

    @staticmethod
    def from_bytes(ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        return AdvUuid16List.from_bytes(AdvServiceSollicitationUuid16List, ad_record)


class AdvServiceSollicitationUuid128List(AdvUuid128List):
    """List of 128-bit Service sollicitation UUIDs.
    """

    def __init__(self, *args):
        """Create a list of 128-bit UUID.
        """
        super().__init__(0x15, *args)

    @staticmethod
    def from_bytes(ad_record):
        """Convert a corresponding AD record into an AdvIncServiceUuid16List instance.
        """
        return AdvUuid128List.from_bytes(AdvServiceSollicitationUuid128List, ad_record)


class AdvServiceData16(AdvDataField):
    """Service Data with 16-bit UUID.
    """

    def __init__(self, uuid, data):
        self.__uuid = uuid
        self.__data = data
        super().__init__(0x16, bytes(uuid.packed + data))

    @property
    def uuid(self):
        return self.__uuid

    @property
    def data(self):
        return self.__data

    @staticmethod
    def from_bytes(adv_record):
        """Create an instance of AdvServiceData16 from serialized record.
        """
        if len(adv_record) >= 2:
            uuid = UUID(unpack('<H', adv_record[:2])[0])
            data = adv_record[2:]
            return AdvServiceData16(uuid, data)
        else:
            raise AdvDataError

class AdvPublicTargetAddr(AdvDataField):
    """Public target address.
    """

    def __init__(self, *addresses):
        """Create a Public Target Address advertising data record.

        :param addresses: One or more :class:`BDAddress` objects.
        """
        # Parse given addresses
        self.__addresses = []
        for address in addresses:
            if isinstance(address, BDAddress):
                self.__addresses.append(address)
            elif isinstance(address, str):
                self.__addresses.append(BDAddress(address))

        super().__init__(0x17, b''.join([addr.value for addr in self.__addresses]))

    def __len__(self):
        return len(self.__addresses)

    def __getitem__(self, index):
        if index >= 0 and index < len(self.__addresses):
            return self.__addresses[index]
        else:
            raise IndexError

    @staticmethod
    def from_bytes(adv_record):
        """Create a AdvPublicTargetAddr from a serialized record.
        """
        if len(adv_record) > 0 and ((len(adv_record) % 6) == 0):
            nb_addr = int(len(adv_record)/6)
            addresses = []
            for i in range(nb_addr):
                addresses.append(
                    BDAddress.from_bytes(adv_record[6*i:6*(i+1)])
                )
            return AdvPublicTargetAddr(*addresses)
        else:
            raise AdvDataError


class AdvRandomTargetAddr(AdvDataField):
    """Random target address.
    """

    def __init__(self, *addresses):
        """Create a Public Target Address advertising data record.

        :param addresses: One or more :class:`BDAddress` objects.
        """
        # Parse given addresses
        self.__addresses = []
        for address in addresses:
            if isinstance(address, BDAddress):
                self.__addresses.append(address)
            elif isinstance(address, str):
                self.__addresses.append(BDAddress(address))

        super().__init__(0x18, b''.join([addr.value for addr in self.__addresses]))

    def __len__(self):
        return len(self.__addresses)

    def __getitem__(self, index):
        if index >= 0 and index < len(self.__addresses):
            return self.__addresses[index]
        else:
            raise IndexError

    @staticmethod
    def from_bytes(adv_record):
        """Create a AdvPublicTargetAddr from a serialized record.
        """
        if len(adv_record) > 0 and ((len(adv_record) % 6) == 0):
            nb_addr = int(len(adv_record)/6)
            addresses = []
            for i in range(nb_addr):
                addresses.append(
                    BDAddress.from_bytes(adv_record[6*i:6*(i+1)])
                )
            return AdvRandomTargetAddr(*addresses)
        else:
            raise AdvDataError

class AdvAppearance(AdvDataField):
    """Device appearance advertising data record.
    """

    def __init__(self, appearance=0x0000):
        """Create an Device appearance advertisement record.

        :param int appearance: Device appearance (16-bit value)
        """
        if appearance >= 0x0000 and appearance <= 0xFFFF:
            self.__appearance = appearance
            super().__init__(0x19, pack('<H', appearance))
        else:
            raise AdvDataError

    @property
    def category(self):
        return (self.__appearance >> 6)

    @property
    def subcategory(self):
        return (self.__appearance & 0x3f)

    @staticmethod
    def from_bytes(adv_record):
        """Create an AdvAppearance object from serialized advertising data record.

        :param bytes adv_record: Serialized data record.
        :rtype: AdvAppearance
        :returns: A new AdvAppearance object that represents the device appearance.
        """
        if len(adv_record) == 2:
            appearance = unpack('<H', adv_record)[0]
            return AdvAppearance(appearance)
        else:
            raise AdvDataError

class AdvURI(AdvDataField):
    """Uniform Resource Identifier advertising data record.
    """

    SUPPORTED_SCHEMES = {
        'data'  : 0x000C,
        'ftp'   : 0x0011,
        'http'  : 0x0016,
        'https' : 0x0017,
        'mailto': 0x0026
    }

    def __init__(self, url):
        url_info = urlparse(url)
        if url_info.scheme and url_info.scheme in AdvURI.SUPPORTED_SCHEMES:
            self.__scheme = url_info.scheme
            scheme = AdvURI.SUPPORTED_SCHEMES[url_info.scheme]
            self.__uri = url_info._replace(scheme='').geturl()
            encoded_uri = pack('<H', scheme) + self.__uri.encode('utf-8')
            super().__init__(0x24, encoded_uri)
        else:
            raise AdvDataError
    
    @staticmethod
    def get_scheme(scheme_value):
        for s in AdvURI.SUPPORTED_SCHEMES:
            if AdvURI.SUPPORTED_SCHEMES[s] == scheme_value:
                return s
        return None

    @property
    def uri(self):
        return self.__uri

    @property
    def scheme(self):
        return self.__scheme

    @staticmethod
    def from_bytes(adv_record):
        if len(adv_record) >= 2:
            scheme = unpack('<H', adv_record[:2])[0]
            uri = adv_record[2:]
            return AdvURI(AdvURI.get_scheme(scheme)+':' + uri.decode('utf-8'))


class AdvAdvertisingInterval(AdvDataField):
    """Advertising Interval record.
    """

    def __init__(self, interval):
        """Create an Advertising Interval record.
        """
        if interval <= 0xFFFF:
            self.__interval = interval
            self.__interval_packed = pack('<H', interval)
        elif interval <= 0xFFFFFF:
            self.__interval = interval
            self.__interval_packed = bytes([
                interval & 0xFF,
                (interval & 0xFF00)>>8,
                (interval & 0xFF0000)>>16
            ])
        elif interval <= 0xFFFFFFFF:
            self.__interval = interval
            self.__interval_packed = pack('<I', interval)
        else:
            raise AdvDataError
        
        super().__init__(0x1A, self.__interval_packed)

    @property
    def interval(self):
        return self.__interval

    @staticmethod
    def from_bytes(adv_record):
        """Create an AdvAdvertisingInterval object from serialized record

        :param bytes adv_record: Serialized AdvAdvertisingInterval record
        :rtype: AdvAdvertisingInterval
        :returns: An instance of AdvAdvertisingInterval representing the advertising interval
        """
        if len(adv_record) == 2:
            interval = unpack('<H', adv_record)[0]
            return AdvAdvertisingInterval(interval)
        elif len(adv_record) == 3:
            interval = adv_record[0] | (adv_record[1]<<8) | (adv_record[2]<<16)
            return AdvAdvertisingInterval(interval)
        elif len(adv_record) == 4:
            interval = unpack('<I', adv_record)[0]
            return AdvAdvertisingInterval(interval)
        else:
            raise AdvDataError

class AdvBluetoothDeviceAddr(AdvDataField):
    """Bluetooth Device Address information record.
    """

    def __init__(self, bd_address, public=False):
        """Create a Bluetooth Device Address advertising data record

        If both `random` and  `public` are set to True, BD address
        will be considered as `public`.

        :param bd_address: Bluetooth Device Address
        :type bd_address: str, BDAddress
        :param bool public: Set to True to specify a public BD address, False to specify a random BD address
        """
        self.__public = public
        
        if isinstance(bd_address, BDAddress):
            address = bd_address
        elif isinstance(bd_address, str):
            address = BDAddress(bd_address)
        else:
            raise AdvDataError

        if public:
            suffix = bytes([0x00])
        else:
            suffix = bytes([0x01])

        super().__init__(0x1B,address.value + suffix)

    @property
    def is_public(self):
        return self.__public

    @property
    def is_random(self):
        return not self.__public

    @staticmethod
    def from_bytes(adv_record):
        """Create an AdvBluetoothDeviceAddr from advertising record.

        :param bytes adv_record: Advertising data record. 
        """
        if len(adv_record) == 7:
            public = (adv_record[6] == 0x00)
            address = BDAddress.from_bytes(adv_record[:6])
            return AdvBluetoothDeviceAddr(address, public=public)
        else:
            raise AdvDataError
    

class AdvLeRole(AdvDataField):
    """LE Role advertising data record.
    """

    ONLY_PERIPHERAL_ROLE = 0x00
    ONLY_CENTRAL_ROLE = 0x01
    PREFERRED_PERIPHERAL_ROLE = 0x02
    PREFERRED_CENTRAL_ROLE = 0x03


    def __init__(self, role):
        """Create an AdvLeRole advertising data record.
        """
        self.__role = role
        if self.__role >= 0 and self.__role < 4:
            super().__init__(0x1C, pack('<B', role))
        else:
            raise AdvDataError

    @property
    def role(self):
        return self.__role

    @staticmethod
    def from_bytes(adv_record):
        """Deserialize a serialized AdvLeRole record

        :param bytes adv_record: Serialized record
        """
        if len(adv_record) == 1:
            role = adv_record[0]
            return AdvLeRole(role)
        else:
            raise AdvDataError

class AdvServiceDataUuid128(AdvDataField):
    """Service Data with 128-bit UUID.
    """

    def __init__(self, uuid, data):
        self.__uuid = uuid
        if self.__uuid.type == UUID.TYPE_128:
            self.__data = data
            super().__init__(0x21, bytes(uuid.packed + data))
        else:
            raise AdvDataError

    @property
    def uuid(self):
        return self.__uuid

    @property
    def data(self):
        return self.__data

    @staticmethod
    def from_bytes(adv_record):
        """Create an instance of AdvServiceDataUuid128 from serialized record.
        """
        if len(adv_record) >= 16:
            uuid = UUID(adv_record[:16])
            data = adv_record[16:]
            return AdvServiceDataUuid128(uuid, data)
        else:
            raise AdvDataError


class AdvLeSupportedFeatures(AdvDataField):
    """LE Supported Features
    """

    def __init__(self, encryption=False, conn_param_update=False, ext_reject_ind=False, slave_features_exchange=False, \
        ping=False, data_packet_length=False, privacy=False, ext_scanner_filter_policies=False):
        # Save parameters
        self.__encryption = encryption
        self.__conn_param_update = conn_param_update
        self.__ext_reject_ind = ext_reject_ind
        self.__slave_features_exchange = slave_features_exchange,
        self.__ping = ping
        self.__data_packet_length = data_packet_length
        self.__privacy = privacy
        self.__ext_scanner_filter_policies = ext_scanner_filter_policies

        # Generate bitmap
        features = 0x00
        if self.__encryption:
            features |= 1
        if self.__conn_param_update:
            features |= (1 << 1)
        if self.__ext_reject_ind:
            features |= (1 << 2)
        if self.__slave_features_exchange:
            features |= (1 << 3)
        if self.__ping:
            features |= (1 << 4)
        if self.__data_packet_length:
            features |= (1 << 5)
        if self.__privacy:
            features |= (1 << 6)
        if self.__ext_scanner_filter_policies:
            features |= (1 << 7)
    
        # Since only 8 bits are used in version 5.3, we code this on a single byte
        super().__init__(0x27, pack('<B', features))

    @property
    def has_encryption(self):
        return self.__encryption

    @property
    def has_conn_param_update(self):
        return self.__conn_param_update

    @property
    def has_ext_reject_ind(self):
        return self.__ext_reject_ind

    @property
    def has_slave_features_exchange(self):
        return self.__slave_features_exchange

    @property
    def has_ping(self):
        return self.__ping

    @property
    def has_data_packet_length(self):
        return self.__data_packet_length

    @property
    def has_privacy(self):
        return self.__privacy

    @property
    def has_ext_scanner_filter_policies(self):
        return self.__ext_scanner_filter_policies

    @staticmethod
    def from_bytes(adv_record):
        """Deserialize an AdvLeSupportedFeatures advertising record.

        :param bytes adv_record: AdvLeSupportedFeatures serialized record
        """
        if len(adv_record) >= 1:
            # Parse features set
            features = 0x00
            for i in range(len(adv_record)):
                features |= (adv_record[i] << (8*i))
            
            # Deduce our flags
            encryption = ((features & 1) != 0)
            conn_param_update = ((features & (1<<1)) != 0)
            ext_reject_ind = ((features & (1<<2)) != 0)
            slave_features_exchange = ((features & (1<<3)) != 0)
            ping = ((features & (1<<4)) != 0)
            data_packet_length = ((features & (1<<5)) != 0)
            privacy = ((features & (1<<6)) != 0)
            ext_scanner_filter_policies = ((features & (1<<7)) != 0)
            return AdvLeSupportedFeatures(
                encryption=encryption,
                conn_param_update=conn_param_update,
                ext_reject_ind=ext_reject_ind,
                slave_features_exchange=slave_features_exchange,
                ping=ping,
                data_packet_length=data_packet_length,
                privacy=privacy,
                ext_scanner_filter_policies=ext_scanner_filter_policies
            )
        else:
            raise AdvDataError


class EddystoneUrl(AdvServiceData16):
    """Eddystone-URL advertising data record.
    """

    SCHEMES = [
        "http://www.",
        "https://www.",
        "http://",
        "https://",
    ]

    EXTENSIONS = [
        ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
        ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
    ]

    def encode_url(self, url):
        i = 0
        data = []

        for s in range(len(self.SCHEMES)):
            scheme = self.SCHEMES[s]
            if url.startswith(scheme):
                data.append(s)
                i += len(scheme)
                break
        else:
            raise AdvDataError

        while i < len(url):
            if url[i] == '.':
                for e in range(len(self.EXTENSIONS)):
                    expansion = self.EXTENSIONS[e]
                    if url.startswith(expansion, i):
                        data.append(e)
                        i += len(expansion)
                        break
                else:
                    data.append(0x2E)
                    i += 1
            else:
                data.append(ord(url[i]))
                i += 1
        return data

    def __init__(self, url):
        """Create an EddystoneUrl advertising data record (Custom service data record).

        :param str url: Url to embed into this Eddystone-URL record.
        """
        eddystone_url = self.encode_url(url)
        print(eddystone_url)
        super().__init__(UUID(0xFEAA), bytes([0x10, 0xF8] + eddystone_url))


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
        0x12: AdvSlaveConnIntervalRange,
        0x14: AdvServiceSollicitationUuid16List,
        0x15: AdvServiceSollicitationUuid128List,
        0x16: AdvServiceData16,
        0x17: AdvPublicTargetAddr,
        0x18: AdvRandomTargetAddr,
        0x19: AdvAppearance,
        0x1A: AdvAdvertisingInterval,
        0x1B: AdvBluetoothDeviceAddr,
        0x1C: AdvLeRole,
        #0x1F: AdvServiceSollicitationUuid32List,
        #0x20: AdvServiceDataUuid32,
        0x21: AdvServiceDataUuid128,
        0x24: AdvURI,
        #0x25: AdvIndoorPositioning,
        #0x26: AdvTransportDiscData,
        0x27: AdvLeSupportedFeatures,
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
