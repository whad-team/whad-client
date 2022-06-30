"""GATT Server and Client implementation
"""
from queue import Queue, Empty
from whad.domain.ble.stack.att import BleAttOpcode, BleAttErrorCode
from whad.domain.ble.stack.gatt.attrlist import GattAttributeDataList, GattGroupTypeItem, \
    GattHandleUUIDItem
from whad.domain.ble.exceptions import InvalidUUIDException
from whad.domain.ble.characteristic import UUID

from struct import unpack, pack


class GattErrorResponse(object):
    def __init__(self, request, handle, reason):
        self.__request = request
        self.__handle = handle
        self.__reason = reason

    @property
    def request(self):
        return self.__request

    @property
    def handle(self):
        return self.__handle

class GattFindInfoRequest(object):
    """GATT Find Information Request
    """
    def __init__(self, start, end):
        """Constructor

        :param int start: Start handle value
        :param int end: End handle value
        """
        self.__start = start
        self.__end = end

    @property
    def start(self):
        return self.__start

    @property
    def end(self):
        return self.__end


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
            super().__init__(2)
        elif self.__format == self.FORMAT_HANDLE_UUID_128:
            super().__init__(16)
        
    @staticmethod
    def from_bytes(data):
        if len(data)>1:
            format = data[0]
            res = GattFindInfoResponse(format)
            item_size = 2 if format == GattFindInfoResponse.FORMAT_HANDLE_UUID_16 else 16
            adl = GattAttributeDataList.from_bytes(data[1:], item_size, GattHandleUUIDItem)
            for item in adl:
                res.append(item)
            return res
        else:
            return None

class GattReadByGroupTypeResponse(GattAttributeDataList):
    """GATT Read By Group Type Response
    """

    def __init__(self, item_size):
        super().__init__(item_size)

    @staticmethod
    def from_bytes(item_size, data):
        res = GattReadByGroupTypeResponse(item_size)
        nb_items = int(len(data)/item_size)
        for i in range(nb_items):
            item = data[i*item_size:(i+1)*item_size]
            res.append(GattGroupTypeItem.from_bytes(item))
        return res


class Gatt(object):

    """Gatt client/server base class

    This class provides a default interface for GATT client and server, handling all possible incoming
    request and sending default responses whenever it is possible.
    """

    def __init__(self, att):
        """Gatt constructor
        """
        self.__att = att
        self.__queue = Queue()

    @property
    def att(self):
        return self.__att

    def on_gatt_message(self, message):
        """Add a GATT message into our message queue

        :param message: GATT message to add to our queue
        """
        self.__queue.put(message, block=True, timeout=None)

    def wait_for_message(self, message_clazz):
        """Wait for a specific message type, other messages are dropped

        :param type message_clazz: Expected message class
        """
        while True:
            msg = self.__queue.get(block=True)
            if isinstance(msg, message_clazz) or isinstance(msg, GattErrorResponse):
                return msg


    def error(self, request, handle, reason):
        """Send ATT Error Response
        """
        self.att.error_response(
            request,
            handle, 
            reason
        )

    def on_error_response(self, request, handle, reason):
        self.on_gatt_message(
            GattErrorResponse(request, handle, reason)
        )

    def on_find_info_request(self, start, end):
        """ATT Find Information Request callback

        By default, this method generates an ATT Error Response with ATTRIBUTE_NOT_FOUND error.

        :param int start: Start handle value
        :param int end: End handle value
        """
        self.error(
            BleAttOpcode.FIND_INFO_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_info_response(self, format, handles):
        """ATT Find Information Response callback

        :param format: Information data format
        :param handles: List of handles
        """
        pass

    def on_find_by_type_value_request(self, start, end, uuid, data):
        """ATT Find By Type Value Request callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid: Type UUID
        :param data: Value
        """
        self.error(
            BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_by_type_value_response(self, handles):
        """ATT Find By Type Value Response callback

        :param handles: List of handles
        """
        pass

    def on_read_by_type_request(self, start, end, uuid):
        """ATT Read By Type Request callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid: Type UUID
        """
        self.error(
            BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_read_by_type_request_128bit(self, start, end, uuid1, uuid2):
        """ATT Read By Type Request with 128-bit UUID callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid1: 128-bit part 1
        :param uuid2: 128-bit part 2
        """
        self.error(
            BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_read_by_type_response(self, length, handles):
        """ATT Read By Type Response callback

        :param int length: Item length
        :param handles: List of handles
        """
        pass

    def on_read_request(self, handle):
        """ATT Read Request callback

        :param int handle: Attribute handle
        """
        self.error(
            BleAttOpcode.READ_REQUEST, handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_response(self, value):
        """ATT Read Response callback

        :param value: Attribute value
        """
        pass

    def on_read_blob_request(self, handle, offset):
        """ATT Read Blob Request callback

        :param int handle: Attribute handle
        :param int offset: Offset of the first byte of data to read
        """
        self.error(
            BleAttOpcode.READ_BLOB_REQUEST, handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_blob_response(self, value):
        """ATT Read Blob Response callback

        :param value: Attribute value
        """
        pass

    def on_read_multiple_request(self, handles):
        """ATT Read Multiple Request callback

        :param handles: List of handles
        """
        self.error(
            BleAttOpcode.READ_BLOB_REQUEST, handles[0], BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_multiple_response(self, values):
        """ATT Read Multiple Response callback

        :param values: Multiple Attribute values
        """
        pass

    def on_read_by_group_type_request(self, start, end, uuid):
        """ATT Read By Group Type Request callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid: Type UUID
        """
        self.error(
            BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )


    def on_read_by_group_type_response(self, response):
        """ATT Read By Group Type Response callback

        :param int item_length: Item length
        :param data: List of items
        """        
        pass
        
    def on_write_request(self, handle, data):
        """ATT Write Request callback

        :param int handle: Attribute handle
        :param data: Attribute value
        """
        self.error(
            BleAttOpcode.WRITE_REQUEST, handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_write_response(self):
        """ATT Write Response callback
        """
        pass

    def on_write_command(self, handle, data):
        """ATT Write Command callback

        :param int handle: Attribute handle
        :param data: Attribute data
        """
        self.error(
            BleAttOpcode.WRITE_REQUEST, handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_prepare_write_request(self, handle, offset, data):
        """ATT Prepare Write request callback

        :param int handle: Attribute handle
        :param int offset: Data offset
        :param data: Attribute data
        """
        self.error(
            BleAttOpcode.PREPARE_WRITE_REQUEST, handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_prepare_write_response(self, handle, offset, data):
        """ATT Prepare Write Response Callback

        :param int handle: Attribute handle
        :param int offset: Data offset
        :param data: Attribute data
        """
        pass

    def on_execute_write_request(self, flags):
        """ATT Execute Write Request callback

        :param int flags: Flags
        """
        pass

    def on_execute_write_response(self):
        """ATT Execute Write Response callback
        """
        pass
        
    def on_handle_value_notification(self, handle, value):
        """ATT Handle Value Notification

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        pass

    def on_handle_value_indication(self, handle, value):
        """ATT Handle Value Indication

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        pass


class GattClient(Gatt):
    """GATT client
    """

    def __init__(self, att):
        super().__init__(att)

    def discover_primary_services(self):
        """Discover remote Primary Services
        """
        # List primary services handles
        primary_services = []
        handle = 1
        while True:
            print('> discover primary services starting from handle %d' % handle)
            # Send a Read By Group Type Request
            self.att.read_by_group_type_request(
                handle,
                0xFFFF,
                0x2800
            )

            msg = self.wait_for_message(GattReadByGroupTypeResponse)
            if isinstance(msg, GattReadByGroupTypeResponse):
                for item in msg:
                    primary_services.append(
                        (item.handle, UUID(item.value))
                    )
                    handle = item.end
                handle += 1
            elif isinstance(msg, GattErrorResponse):
                break
        print(primary_services)

    def on_read_by_group_type_response(self, response):
        """ATT Read By Group Type Response callback

        :param int item_length: Item length
        :param data: List of items
        """
        print('>> Got answer')
        self.on_gatt_message(response)
        

    
    

    