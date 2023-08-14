from .attrlist import gatt_attr_list_iter, GattAttributeDataList, GattHandleUUIDItem, GattHandleItem, \
    GattAttributeValueItem, GattGroupTypeItem
from whad.ble.profile.attribute import UUID


class GattDataHolder(object):
    def __init__(self, **kwargs):
        self.__data = {}
        for arg in kwargs:
            self.__data[arg] = kwargs[arg]

    def __getattr__(self, name):
        if name in self.__data:
            return self.__data[name]
        else:
            raise AttributeError
        

class GattErrorResponse(GattDataHolder):
    def __init__(self, request, handle, reason):
        super().__init__(
            request=request,
            handle=handle,
            reason=reason
        )

class GattFindInfoRequest(GattDataHolder):
    """GATT Find Information Request
    """
    def __init__(self, start: int, end: int):
        super().__init__(
            start=start,
            end=end
        )


class GattFindInfoResponse(GattAttributeDataList):
    """GATT Find Information Response
    """

    FORMAT_HANDLE_UUID_16 = 1
    FORMAT_HANDLE_UUID_128 = 2          

    def __init__(self, format):
        """Store handles list

        :param int format: Handle format
        :param bytes handles_list: Handles data
        """
        self.__format = format
        self.__handles = []
        if self.__format == self.FORMAT_HANDLE_UUID_16:
            super().__init__(4)
        elif self.__format == self.FORMAT_HANDLE_UUID_128:
            super().__init__(18)
        
    @staticmethod
    def from_bytes(format: int, data: bytes):
        if len(data)>1:
            res = GattFindInfoResponse(format)
            item_size = 4 if format == GattFindInfoResponse.FORMAT_HANDLE_UUID_16 else 18
            adl = GattAttributeDataList.from_bytes(data, item_size, GattHandleUUIDItem)
            for item in adl:
                res.append(item)
            return res
        else:
            return None

class GattFindByTypeValueRequest(GattDataHolder):
    def __init__(self, start: int, end: int, attr_type: UUID, attr_value: bytes):
        super().__init__(
            start=start,
            end=end,
            type=attr_type,
            value=attr_value
        )

class GattFindByTypeValueResponse(GattAttributeDataList):
    def __init__(self):
        super().__init__(4)

    @staticmethod
    def from_bytes(data: bytes):
        res = GattFindByTypeValueResponse()
        for item in gatt_attr_list_iter(4, data):
            res.append(GattHandleItem.from_bytes(item))
        return res

class GattReadByTypeRequest(GattDataHolder):
    def __init__(self, start: int, end: int, attr_type: UUID):
        super().__init__(
            start=start,
            end=end,
            type=attr_type
        )

class GattReadByTypeRequest128(GattDataHolder):
    def __init__(self, start: int, end: int, attr_type1: UUID, attr_type2: UUID):
        super().__init__(
            start=start,
            end=end,
            type1=attr_type1,
            type2=attr_type2
        )


class GattReadByTypeResponse(GattAttributeDataList):
    def __init__(self, item_size):
        super().__init__(item_size)

    @staticmethod
    def from_bytes(item_size: int, data: bytes):
        res = GattReadByTypeResponse(item_size)
        for item in gatt_attr_list_iter(item_size, data):
            res.append(GattAttributeValueItem.from_bytes(item))
        return res

class GattReadRequest(GattDataHolder):
    def __init__(self, handle: int):
        super().__init__(
            handle=handle
        )

class GattReadResponse(GattDataHolder):
    def __init__(self, value: bytes):
        super().__init__(
            value=value
        )

class GattReadBlobRequest(GattDataHolder):
    def __init__(self, handle: int, offset: int):
        super().__init__(
            handle=handle,
            offset=offset
        )

class GattReadBlobResponse(GattDataHolder):
    def __init__(self, value: bytes):
        super().__init__(
            value=value
        )

class GattReadMultipleRequest(GattDataHolder):
    def __init__(self, handles: bytes):
        super().__init__(
            handles=handles
        )

class GattReadMultipleResponse(GattDataHolder):
    def __init__(self, values: bytes):
        super().__init__(
            values=values
        )

class GattReadByGroupTypeRequest(GattDataHolder):
    def __init__(self, start: int, end: int, group_type: UUID):
        super().__init__(
            start=start,
            end=end,
            type=group_type
        )

class GattReadByGroupTypeResponse(GattAttributeDataList):
    """GATT Read By Group Type Response
    """

    def __init__(self, item_size: int):
        super().__init__(item_size)

    @staticmethod
    def from_bytes(item_size, data):
        res = GattReadByGroupTypeResponse(item_size)
        for item in gatt_attr_list_iter(item_size, data):
            res.append(GattGroupTypeItem.from_bytes(item))
        return res

class GattWriteRequest(GattDataHolder):
    def __init__(self, handle: int, value: bytes):
        super().__init__(
            handle=handle,
            value=value
        )

class GattWriteResponse(GattDataHolder):
    def __init__(self):
        super().__init__()

class GattWriteCommand(GattDataHolder):
    def __init__(self, handle: int, value: bytes):
        super().__init__(
            handle=handle,
            value=value
        )

class GattPrepareWriteRequest(GattDataHolder):
    def __init__(self, handle: int, offset: int, value: bytes):
        super().__init__(
            handle=handle,
            offset=offset,
            value=value
        )

class GattPrepareWriteResponse(GattDataHolder):
    def __init__(self, handle: int, offset: int, value: bytes):
        super().__init__(
            handle=handle,
            offset=offset,
            value=value
        )

class GattExecuteWriteRequest(GattDataHolder):
    def __init__(self, flags: int):
        super().__init__(flags=flags)

class GattExecuteWriteResponse(GattDataHolder):
    def __init__(self):
        super().__init__()

class GattHandleValueNotification(GattDataHolder):
    def __init__(self, handle: int, value: bytes):
        super().__init__(
            handle=handle,
            value=value
        )

class GattHandleValueIndication(GattDataHolder):
    def __init__(self, handle: int, value: bytes):
        super().__init__(
            handle=handle,
            value=value
        )

class GattHandleValueConfirmation(GattDataHolder):
    def __init__(self):
        super().__init__()

class GattExchangeMtuResponse(GattDataHolder):
    def __init__(self, mtu: int):
        super().__init__(
            mtu=mtu
        )
