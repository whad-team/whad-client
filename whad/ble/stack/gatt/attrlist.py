""" BLE GATT Attribute Data List and items.
"""
from struct import pack, unpack

from whad.ble.profile import UUID

class GattListItem(object):
    """Template class for a GATT Attribute List Item
    """

    @staticmethod
    def from_bytes(data):
        """Convert a byte array into a list item

        :param bytes data: Data to convert to a list item
        """
        return None

    def to_bytes(self):
        """Serialize list item to bytes
        """
        return b''

    def size(self):
        """Get list item size
        """
        return len(self.to_bytes())


class GattHandleItem(GattListItem):
    """GATT Attribute Data List item used to store start and end handle values.
    """
    def __init__(self, handle, end):
        """
        :param int handle: Attribute handle
        :param int end: Group end
        """
        self.__handle = handle
        self.__end = end

    @property
    def handle(self):
        """Return attribute handle value
        """
        return self.__handle

    @property
    def end(self):
        """Return group end handle value
        """
        return self.__end

    @staticmethod
    def from_bytes(data):
        """Convert bytes to a GattHandleItem object

        :param bytes data: Serialized handle/end pair
        """
        if len(data) == 4:
            handle, end = unpack('<HH', data)
            return GattHandleItem(handle, end)
        else:
            return None

    def to_bytes(self):
        return pack('<HH', self.handle, self.end)

class GattHandleUUIDItem(GattListItem):
    """GATT Attribute Data List item that stores a handle/UUID{16,128} pair.
    """
    def __init__(self, handle, uuid):
        """
        :param int handle: Attribute handle
        :param UUID uuid: Attribute UUID
        """
        self.__handle = handle
        self.__uuid = uuid

    @property
    def handle(self):
        return self.__handle

    @property
    def uuid(self):
        return self.__uuid

    @staticmethod
    def from_bytes(data):
        if len(data)>=4:
            handle = unpack('<H', data[:2])[0]
            uuid = UUID(data[2:])
            return GattHandleUUIDItem(handle, uuid)
        else:
            return None

    def to_bytes(self):
        return pack('<H', self.__handle) + self.__uuid.packed

    def size(self):
        return len(self.to_bytes())

class GattGroupTypeItem(GattListItem):
    """GATT Attribute Data list item that stores group information (start handle, end handle, value).
    """
    def __init__(self, handle, end, value):
        self.__handle = handle
        self.__end = end
        self.__value = value

    @property
    def handle(self):
        return self.__handle

    @property
    def end(self):
        return self.__end

    @property
    def value(self):
        return self.__value

    @staticmethod
    def from_bytes(data):
        if len(data)>4:
            handle, end = unpack('<HH', data[:4])
            value = data[4:]
            return GattGroupTypeItem(handle, end, value)
        return None

    def to_bytes(self):
        return pack('<HH', self.__handle, self.__end) + bytes(self.__value)

class GattAttributeValueItem(GattListItem):
    """GATT Attribute Data list item that stores a handle/value pair.
    """
    def __init__(self, handle, value):
        """
        :param int handle: Attribute handle
        :param bytes value: Attribute value
        """
        self.__handle = handle
        self.__value = value

    @property
    def handle(self):
        return self.__handle

    @property
    def value(self):
        return self.__value

    @staticmethod
    def from_bytes(data):
        if len(data) > 2:
            handle = unpack('<H', data[:2])[0]
            value = data[2:]
            return GattAttributeValueItem(handle, value)
        return None

    def to_bytes(self):
        return pack('<H', self.__handle) + bytes(self.__value)

    def size(self):
        return len(self.to_bytes())

class GattAttributeDataList(object):
    """Generic GATT Attribute Data List class.

    This class can be inherited to provide a list behavior and serialization/deserialization
    functions. A GATT Attribute Data List item class must be provided.
    """
    def __init__(self, item_size):
        self.__item_size = item_size
        self.__items = []

    def __len__(self):
        return len(self.__items)

    def __getitem__(self, idx):
        if idx >= 0 and idx < len(self.__items):
            return self.__items[idx]
        else:
            raise IndexError

    def append(self, item):
        if item.size() == self.__item_size:
            self.__items.append(item)
        else:
            print('wrong size (%d instead of %d)' % (item.size(), self.__item_size))

    def remove(self, item):
        self.__items.remove(item)

    @staticmethod
    def from_bytes(data, item_size, item_clazz):
        """Create GattAttributeDataList from raw data

        :param bytes data: Raw data to parse
        """
        adl = GattAttributeDataList(item_size)
        nb_items = int(len(data)/item_size)
        for i in range(nb_items):
            item = data[i*item_size:(i+1)*item_size]
            adl.append(item_clazz.from_bytes(item))
        return adl

    def to_bytes(self):
        output=b''
        for item in self.__items:
            output += item.to_bytes()
        return output


def gatt_attr_list_iter(item_size, data):
    nb_items = int(len(data)/item_size)
    for i in range(nb_items):
        yield data[i*item_size:(i+1)*item_size]
