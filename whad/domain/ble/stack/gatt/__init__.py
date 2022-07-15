"""GATT Server and Client implementation
"""
from time import time
from queue import Queue, Empty
from struct import unpack, pack

from whad.domain.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.domain.ble.stack.att.exceptions import InvalidHandleValueError, error_response_to_exc, InsufficientAuthenticationError,\
    InsufficientAuthorizationError, InsufficientEncryptionKeySize, ReadNotPermittedError, AttErrorCode
from whad.domain.ble.stack.gatt.message import *
from whad.domain.ble.stack.gatt.exceptions import GattTimeoutException
from whad.domain.ble.profile import GenericProfile
from whad.domain.ble.characteristic import Characteristic, ClientCharacteristicConfig
from whad.domain.ble.service import PrimaryService, SecondaryService


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

    def wait_for_message(self, message_clazz, timeout=30.0):
        """Wait for a specific message type or error, other messages are dropped

        :param type message_clazz: Expected message class
        :param float timeout: Timeout value (default: 30 seconds)
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__queue.get(timeout=0.5)
                if isinstance(msg, message_clazz) or isinstance(msg, GattErrorResponse):
                    return msg
            except Empty:
                pass
        raise GattTimeoutException


    def error(self, request, handle, reason):
        """Send ATT Error Response
        """
        self.att.error_response(
            request,
            handle,
            reason
        )

    def on_error_response(self, error):
        self.on_gatt_message(error)

    def on_find_info_request(self, start, end):
        """ATT Find Information Request callback

        By default, this method generates an ATT Error Response with ATTRIBUTE_NOT_FOUND error.

        :param int start: Start handle value
        :param int end: End handle value
        """
        self.error(
            BleAttOpcode.FIND_INFO_REQUEST, start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_info_response(self, response):
        """ATT Find Information Response callback

        :param format: Information data format
        :param handles: List of handles
        """
        pass

    def on_find_by_type_value_request(self, request):
        """ATT Find By Type Value Request callback

        :param GattFindByTypeValueRequest request: Request
        """
        self.error(
            BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST, request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_by_type_value_response(self, response):
        """ATT Find By Type Value Response callback

        :param GattFindByTypeValueResponse response: Response message
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

    def on_read_by_type_response(self, response):
        """ATT Read By Type Response callback

        :param GattReadByTypeResponse response: Response
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

    def on_write_response(self, response):
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

    def on_handle_value_notification(self, notification):
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
        self.__model = GenericProfile()
        self.__notification_callbacks = {}

    ###################################
    # Supported response handlers
    ###################################

    def on_read_by_group_type_response(self, response):
        """ATT Read By Group Type Response callback

        """
        self.on_gatt_message(response)

    def on_read_by_type_response(self, response):
        """ATT Read By Type Response callback

        :param GattReadByTypeResponse response: Response
        """
        self.on_gatt_message(response)

    def on_find_info_response(self, response):
        """ATT Find Information Response callback

        :param format: Information data format
        :param handles: List of handles
        """
        self.on_gatt_message(response)

    def on_read_response(self, response):
        """ATT Read Response callback

        :param value: Attribute value
        """
        self.on_gatt_message(response)

    def on_read_by_type_response(self, response):
        """ATT Read By Type Response callback

        :param GattReadByTypeResponse response: Response
        """
        self.on_gatt_message(response)

    def on_read_blob_response(self, response):
        """ATT Read Blob Response callback

        :param value: Attribute value
        """
        self.on_gatt_message(response)

    def on_write_response(self, response):
        """ATT Write Response callback
        """
        self.on_gatt_message(response)

    def on_find_by_type_value_response(self, response):
        """ATT Find By Type Value Response callback

        :param GattFindByTypeValueResponse response: Response message
        """
        self.on_gatt_message(response)


    def on_handle_value_notification(self, notification):
        """ATT Handle Value Notification

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        if notification.handle in self.__notification_callbacks:
            self.__notification_callbacks[notification.handle](
                notification.handle,
                notification.value,
                indicate=False
            )

    def on_handle_value_indication(self, notification):
        """ATT Handle Value Indication

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        if notification.handle in self.__notification_callbacks:
            self.__notification_callbacks[notification.handle](
                notification.handle,
                notification.value,
                indicate=True
            )
        self.att.handle_value_confirmation()

    ###################################
    # GATT procedures
    ###################################

    def register_notification_callback(self, handle, cb):
        self.__notification_callbacks[handle] = cb

    def unregister_notification_callback(self, handle):
        del self.__notification_callbacks[handle]

    def discover_primary_service_by_uuid(self, uuid):
        """Discover a primary service by its UUID.

        :param UUID uuid: Service UUID
        :return: Service if service has been found, None otherwise
        """
        self.att.find_by_type_value_request(
            1,
            0xFFFF,
            0x2800,
            uuid.packed
        )
        msg = self.wait_for_message(GattFindByTypeValueResponse)
        if isinstance(msg, GattFindByTypeValueResponse):
            for item in msg:
                return PrimaryService(
                    uuid=None,
                    handle=item.handle,
                    end_handle=item.end
                )
        elif isinstance(msg, GattErrorResponse):
            if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                return None
            else:
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)


    def discover_primary_services(self):
        """Discover remote Primary Services.

        This function will yield every discovered primary service.
        """
        # List primary services handles
        handle = 1
        while True:
            # Send a Read By Group Type Request
            self.att.read_by_group_type_request(
                handle,
                0xFFFF,
                0x2800
            )

            msg = self.wait_for_message(GattReadByGroupTypeResponse)
            if isinstance(msg, GattReadByGroupTypeResponse):
                for item in msg:
                    yield PrimaryService(
                        uuid=UUID(item.value),
                        handle=item.handle,
                        end_handle=item.end
                    )
                    handle = item.end

                    if handle == 0xFFFF:
                        return

                handle += 1
            elif isinstance(msg, GattErrorResponse):
                if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                    break
                else:
                    error_response_to_exc(msg.reason, msg.request, msg.handle)

    def discover_secondary_services(self):
        """Discover remote Secondary Services.
        """
        # List primary services handles
        handle = 1
        while True:
            # Send a Read By Group Type Request
            self.att.read_by_group_type_request(
                handle,
                0xFFFF,
                0x2801
            )

            msg = self.wait_for_message(GattReadByGroupTypeResponse)
            if isinstance(msg, GattReadByGroupTypeResponse):
                for item in msg:
                    yield SecondaryService(
                        uuid=UUID(item.value),
                        handle=item.handle,
                        end_handle=item.end
                    )
                    handle = item.end

                    if handle == 0xFFFF:
                        return

                handle += 1
            elif isinstance(msg, GattErrorResponse):
                if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                    break
                else:
                    error_response_to_exc(msg.reason, msg.request, msg.handle)

    def discover_characteristics(self, service):
        """
        Discover service characteristics
        """
        if isinstance(service, PrimaryService):
            handle = service.handle
        else:
            return

        while handle <= service.end_handle:
            self.att.read_by_type_request(
                handle,
                service.end_handle,
                0x2803
            )

            msg =self.wait_for_message(GattReadByTypeResponse)
            if isinstance(msg, GattReadByTypeResponse):
                for item in msg:
                    charac_properties = item.value[0]
                    #charac_handle = unpack('<H', item.value[1:3])[0]
                    charac_handle = item.handle
                    charac_value_handle = unpack('<H', item.value[1:3])[0]
                    charac_uuid = UUID(item.value[3:])
                    charac = Characteristic(
                        uuid=charac_uuid,
                        properties=charac_properties
                    )
                    charac.handle = charac_handle
                    charac.value_handle = charac_value_handle
                    handle = charac.handle+1
                    yield charac

            elif isinstance(msg, GattErrorResponse):
                if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                    break
                else:
                    error_response_to_exc(msg.reason, msg.request, msg.handle)

    def discover_characteristic_descriptors(self, characteristic):
        """Find characteristic descriptor
        """
        if isinstance(characteristic, Characteristic):
            handle = characteristic.value_handle + 1
            end_handle = self.__model.find_characteristic_end_handle(characteristic.handle)
            while handle <= end_handle:
                self.att.find_info_request(
                    handle,
                    end_handle
                )

                msg = self.wait_for_message(GattFindInfoResponse)
                if isinstance(msg, GattFindInfoResponse):
                    for descriptor in msg:
                        handle = descriptor.handle

                        # End discovery if returned handle is Ending Handle (0xFFFF)
                        if handle == 0xFFFF:
                            return

                        yield(descriptor)
                elif isinstance(msg, GattErrorResponse):
                    if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                        break
                    else:
                        error_response_to_exc(msg.reason, msg.request, msg.handle)

                handle += 1

    def discover(self):
        # Discover services
        services = []
        for service in self.discover_primary_services():
            services.append(service)
        for service in services:
            for characteristic in self.discover_characteristics(service):
                service.add_characteristic(characteristic)
            self.__model.add_service(service)

        # Searching for descriptors
        for service in self.__model.services():
            for characteristic in service.characteristics():
                for descriptor in self.discover_characteristic_descriptors(characteristic):
                    if descriptor.uuid == UUID(0x2902):
                        characteristic.add_descriptor(
                            ClientCharacteristicConfig(
                                handle=descriptor.handle
                            )
                        )
        print(self.__model)


    def read(self, handle):
        """Read a characteristic or a descriptor.

        :param int handle: Handle of the attribute to read (descriptor or characteristic)
        """
        self.att.read_request(gatt_handle=handle)
        msg = self.wait_for_message(GattReadResponse)
        if isinstance(msg, GattReadResponse):
            return msg.value
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    def read_long(self, handle):
        """Read a long characteristic or descriptor

        :param int handle: Handle of the attribute to read (descriptor or characteristic)
        """
        value=b''
        offset=0
        while True:
            self.att.read_blob_request(handle, offset)
            msg = self.wait_for_message(GattReadBlobResponse)
            if isinstance(msg, GattReadBlobResponse):
                if msg.value is not None:
                    value += msg.value
                    offset += len(msg.value)
                else:
                    break
            elif isinstance(msg, GattErrorResponse):
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)
        return value



    def write(self, handle, value):
        """Write data to a characteristic or a descriptor

        :param int handle: Target characteristic or descriptor handle
        :param bytes value: Data to write
        """
        self.att.write_request(
            handle,
            value
        )
        msg = self.wait_for_message(GattWriteResponse)
        if isinstance(msg, GattWriteResponse):
            return True
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)


    def read_characteristic_by_uuid(self, uuid, start=1, end=0xFFFF):
        """Read a characteristic given its UUID if its handle is comprised in a given range.

        :param UUID uuid: Characteristic UUID
        :param int start: Start handle value
        :param int end: End handle value
        """
        self.att.read_by_type_request(start, end, uuid.value())
        msg = self.wait_for_message(GattReadByTypeResponse)
        if isinstance(msg, GattReadByTypeResponse):
            output = []
            for item in msg:
                output.append(item.value)
            if len(output) == 1:
                return output[0]
            else:
                return output
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    def services(self):
        return self.__model.services()
