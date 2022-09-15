"""GATT Server and Client implementation
"""
from time import time
from queue import Queue, Empty
from struct import unpack, pack

import logging
logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.ble.stack.gatt').setLevel(logging.INFO)

from whad.ble.exceptions import HookReturnValue, HookReturnAuthRequired,\
    HookReturnAccessDenied, HookReturnGattError, HookReturnNotFound
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.stack.att.exceptions import InvalidHandleValueError, error_response_to_exc, InsufficientAuthenticationError,\
    InsufficientAuthorizationError, InsufficientEncryptionKeySize, ReadNotPermittedError, AttErrorCode
from whad.ble.stack.gatt.message import *
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.profile import GenericProfile
from whad.ble.profile.characteristic import Characteristic, CharacteristicDescriptor, ClientCharacteristicConfig, CharacteristicValue
from whad.ble.profile.service import PrimaryService, SecondaryService


class Gatt(object):

    """Gatt client/server base class

    This class provides a default interface for GATT client and server, handling all possible incoming
    request and sending default responses whenever it is possible.
    """

    def __init__(self, att=None):
        """Gatt constructor
        """
        self.__att = att
        self.__queue = Queue()

    def attach(self, att):
        """Attach this GATT instance to the underlying ATT layer
        """
        self.__att = att

    @property
    def att(self):
        return self.__att

    def indicate(self, characteristic):
        """Send an indication to a GATT client. Not implemented by default.
        """
        pass

    def notify(self, characteristic):
        """Send a notfication to a GATT client. Not implemented by default.
        """
        pass

    def on_gatt_message(self, message):
        """Add a GATT message into our message queue

        :param message: GATT message to add to our queue
        """
        self.__queue.put(message, block=True, timeout=None)

    def wait_for_message(self, message_clazz, timeout=5.0):
        """Wait for a specific message type or error, other messages are dropped

        :param type message_clazz: Expected message class
        :param float timeout: Timeout value (default: 30 seconds)
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__queue.get(block=False,timeout=0.5)
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

    def on_terminated(self):
        """Called when the underlying connection has been terminated.
        """
        pass

class GattClient(Gatt):
    """GATT client
    """

    def __init__(self):
        super().__init__()
        self.__model = GenericProfile()
        self.__notification_callbacks = {}

    @property
    def model(self):
        return self.__model

    def set_model(self, model):
        if isinstance(model, GenericProfile):
            self.__model = model

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
                indication=False
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
                indication=True
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
                                characteristic,
                                handle=descriptor.handle
                            )
                        )

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

    def read_blob(self, handle, offset=0):
        """Read a characteristic or a descriptor starting from `offset`.

        :param int handle: Handle of the characteristic value or descriptor to read.
        :param int offset: Start reading from this offset value (default: 0)
        """
        self.att.read_blob_request(handle, offset)
        msg = self.wait_for_message(GattReadBlobResponse)
        if isinstance(msg, GattReadBlobResponse):
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

    def write_command(self, handle, value):
        """Write data to a characteristic or a descriptor, do not expect an answer.

        :param int handle: Target characteristic or descriptor handle
        :param bytes value: Data to write
        """
        self.att.write_command(
            handle,
            value
        )

        # Write command does not cause the GATT server to return a response.
        return True

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


class GattServer(Gatt):
    """
    BLE GATT server
    """

    def __init__(self, model):
        """Instanciate our GATT server and use the provided device model

        :param DeviceModel model: Device model object
        """
        super().__init__()
        self.__model = model

        # Prepared write queues
        self.__write_queues = {}

        # Subscribed characteristics
        self.__subscribed_characs = []

    ###################################
    # Supported response handlers
    ###################################


    ###################################
    # GATT procedures
    ###################################

    def notify(self, characteristic):
        """Sends a notification to a GATT client for a given characteristic.

        :param Characteristic characteristic: Characteristic to notify the GATT client about.
        """
        try:
            # Call model callback
            service = self.__model.find_service_by_characteristic_handle(characteristic.handle)
            self.__model.on_notification(
                service,
                characteristic,
                characteristic.value[:self.att.local_mtu-3]
            )

            # Send notification
            self.att.handle_value_notification(
                characteristic.value_handle,
                characteristic.value[:self.att.local_mtu-3]
            )
        except HookReturnValue as value_override:
            # Return overriden value
            self.att.handle_value_notification(
                characteristic.value_handle,
                value_override.value[:self.att.local_mtu-3]
            )

    def indicate(self, characteristic):
        """Sends an indication to a GATT client for a given characteristic.

        :param Characteristic characteristic: Characteristic to notify the GATT client about.
        """
        try:
            # Call model callback
            service = self.__model.find_service_by_characteristic_handle(characteristic.handle)
            self.__model.on_indication(
                service,
                characteristic,
                characteristic.value[:self.att.local_mtu-3]
            )

            # Send notification
            self.att.handle_value_indication(
                characteristic.value_handle,
                characteristic.value[:self.att.local_mtu-3]
            )
        except HookReturnValue as value_override:
            # Return overriden value
            self.att.handle_value_indication(
                characteristic.value_handle,
                value_override.value[:self.att.local_mtu-3]
            )

    def on_find_info_request(self, request):
        """Find information request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.__model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:
            
            # Get MTU
            mtu = self.att.local_mtu

            # Get item size (UUID size + 2)
            uuid_size = len(attrs[attrs_handles[0]].type_uuid.packed)
            if uuid_size == 2:
                item_format = 1
            else:
                item_format = 2
            item_size = uuid_size + 2
            max_nb_items = int((mtu - 2) / item_size)
            
            # Create our datalist
            datalist = GattAttributeDataList(item_size)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    attr_obj = attrs[handle]
                    if len(attr_obj.type_uuid.packed) == uuid_size:
                        datalist.append(
                            GattHandleUUIDItem(
                                attr_obj.handle,
                                attr_obj.type_uuid
                            )
                        )
                else:
                    break
            
            # Once datalist created, send answer
            datalist_raw = datalist.to_bytes()
            self.att.find_info_response(item_format, datalist_raw)
        else:
            self.error(
               BleAttOpcode.FIND_INFO_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )


    def on_read_request(self, request):
        """Read attribute value (if any)

        :param int handle: Characteristic or descriptor handle
        """
        try:
            # Search attribute by handle and send respons
            attr = self.__model.find_object_by_handle(request.handle)

            # Ensure attribute is a readable characteristic value or a descriptor
            if isinstance(attr, CharacteristicValue):

                # Check characteristic is readable
                charac = self.__model.find_object_by_handle(request.handle - 1)

                if charac.readable():
                    try:
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)
                        self.__model.on_characteristic_read(
                            service,
                            charac,
                            0,
                            self.att.local_mtu - 1
                        )
                        
                        # Make sure the returned value matches the boundaries
                        value = charac.value[:self.att.local_mtu - 1]

                        self.att.read_response(
                            value
                        )
                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        value = force_value.value[:self.att.local_mtu - 1]

                        self.att.read_response(
                            value
                        )
                    except HookReturnAuthRequired as auth_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAccessDenied as access_denied:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.READ_NOT_PERMITTED
                        )
                    except HookReturnNotFound as not_found:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                    except HookReturnGattError as gatt_error:
                        self.error(
                            gatt_error.request if gatt_error.request is not None else BleAttOpcode.READ_REQUEST,
                            gatt_error.handle if gatt_error.handle is not None else request.handle,
                            gatt_error.error if gatt_error.error is not None else BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                else:
                    # Characteristic is not readable
                    self.error(
                        BleAttOpcode.READ_REQUEST,
                        request.handle,
                        BleAttErrorCode.READ_NOT_PERMITTED
                    )
            elif isinstance(attr, CharacteristicDescriptor):
                # Make sure the returned value matches the boundaries
                self.att.read_response(
                    attr.value[:self.att.local_mtu - 1]
                )

        except IndexError as e:
            self.error(
                BleAttOpcode.READ_REQUEST,
                request.handle,
                BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )


    def on_read_blob_request(self, request: GattReadBlobRequest):
        """Read blob request
        """
        try:
            # Search attribute by handle and send response
            attr = self.__model.find_object_by_handle(request.handle)

            if request.offset < len(attr.value):

                # If attribute is a characteristic, make sure it is readable
                # before returning a value.
                if isinstance(attr, CharacteristicValue):
                    try:
                        charac = self.__model.find_object_by_handle(request.handle - 1)
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)
                        if not charac.readable():
                            self.error(
                                BleAttOpcode.READ_BLOB_REQUEST,
                                request.handle,
                                BleAttErrorCode.READ_NOT_PERMITTED
                            )
                            return

                        # Call our characteristic read hook
                        self.__model.on_characteristic_read(
                            service,
                            charac,
                            request.offset,
                            self.att.local_mtu - 1
                        )

                        # Make sure the returned value matches the boundaries
                        value = charac.value[request.offset:request.offset + self.att.local_mtu - 1]

                        self.att.read_blob_response(
                            value
                        ) 

                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        value = force_value.value[:self.att.local_mtu - 1]

                        self.att.read_blob_response(
                            value
                        )
                    except HookReturnAuthRequired as auth_error:
                        self.error(
                            BleAttOpcode.READ_BLOB_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAccessDenied as access_denied:
                        self.error(
                            BleAttOpcode.READ_BLOB_REQUEST,
                            request.handle,
                            BleAttErrorCode.READ_NOT_PERMITTED
                        )
                    except HookReturnNotFound as not_found:
                        self.error(
                            BleAttOpcode.READ_BLOB_REQUEST,
                            request.handle,
                            BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                    except HookReturnGattError as gatt_error:
                        self.error(
                            gatt_error.request if gatt_error.request is not None else BleAttOpcode.READ_REQUEST,
                            gatt_error.handle if gatt_error.handle is not None else request.handle,
                            gatt_error.error if gatt_error.error is not None else BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )                
                elif isinstance(attr, CharacteristicDescriptor):
                    # Valid offset, return data[offset:offset + MTU - 1]
                    self.att.read_blob_response(
                        attr.value[request.offset:request.offset + self.att.local_mtu - 1]
                    )
            elif request.offset == len(attr.value):
                # Special case: when offset == attribute length then return empty data
                self.att.read_blob_response(b'')
            else:
                # Invalid offset
                self.error(
                    BleAttOpcode.READ_BLOB_REQUEST,
                    request.handle,
                    BleAttErrorCode.INVALID_OFFSET
                )
        except IndexError as e:
            # Attribute not found
            self.error(
                BleAttOpcode.READ_BLOB_REQUEST,
                request.handle,
                BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        

    def on_write_request(self, request):
        """Write request for characteristic or descriptor value
        """
        try:
            # Retrieve attribute from model
            attr = self.__model.find_object_by_handle(request.handle)
            if isinstance(attr, CharacteristicValue):
                # Check the corresponding characteristic is writeable
                charac = self.__model.find_object_by_handle(request.handle - 1)
                if charac.writeable():
                    # Retrieve corresponding service info
                    service = self.__model.find_service_by_characteristic_handle(charac.handle)

                    try:
                        # Trigger our write hook
                        self.__model.on_characteristic_write(
                            service,
                            charac,
                            0,
                            request.value,
                            False
                        )

                        # Update attribute value
                        attr.value = request.value
                        self.att.write_response()

                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        attr.value = force_value.value
                        self.att.write_response()
                    except HookReturnAuthRequired as auth_error:
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAccessDenied as access_denied:
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.READ_NOT_PERMITTED
                        )
                    except HookReturnNotFound as not_found:
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                    except HookReturnGattError as gatt_error:
                        self.error(
                            gatt_error.request if gatt_error.request is not None else BleAttOpcode.READ_REQUEST,
                            gatt_error.handle if gatt_error.handle is not None else request.handle,
                            gatt_error.error if gatt_error.error is not None else BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                else:
                    self.error(
                        BleAttOpcode.WRITE_REQUEST,
                        request.handle,
                        BleAttErrorCode.WRITE_NOT_PERMITTED
                    )
            elif isinstance(attr, ClientCharacteristicConfig):
                # Fixed length, make sure size <= 2.
                if len(request.value) <= 2:
                    attr.value = request.value + attr.value[len(request.value):]
                    self.att.write_response()

                    # Notify our model
                    if attr.config == 0x0001:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic notification callback
                        charac.set_notification_callback(self.notify)

                        self.__model.on_characteristic_subscribed(
                            service,
                            charac,
                            notification=True
                        )
                    elif attr.config == 0x0002:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic indication callback
                        charac.set_indication_callback(self.indicate)

                        self.__model.on_characteristic_subscribed(
                            service,
                            charac,
                            indication=True
                        )
                    elif attr.config == 0x0000:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Unset characteristic indication and notification callbacks
                        charac.set_notification_callback(None)
                        charac.set_indication_callback(None)

                        # Notify model
                        self.__model.on_characteristic_unsubscribed(
                            service,
                            charac
                        )
                else:
                    # Wrong length
                    self.error(
                        BleAttOpcode.WRITE_REQUEST,
                        request.handle,
                        BleAttErrorCode.INVALID_ATTR_VALUE_LENGTH
                    )
        except IndexError:
            self.error(
                BleAttOpcode.WRITE_REQUEST,
                request.handle,
                BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    def on_write_command(self, request):
        """Write command (without response)
        """
        try:
            # Retrieve attribute from model
            attr = self.__model.find_object_by_handle(request.handle)
            if isinstance(attr, CharacteristicValue):
                # Check the corresponding characteristic is writeable
                charac = self.__model.find_object_by_handle(request.handle - 1)
                if charac.writeable():
                    # Retrieve corresponding service info
                    service = self.__model.find_service_by_characteristic_handle(charac.handle)

                    try:
                        # Trigger our write hook
                        value =  self.__model.on_characteristic_write(
                            service,
                            charac,
                            0,
                            request.value,
                            True
                        )

                        # Update attribute value
                        attr.value = request.value
                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        attr.value = force_value.value
                    except HookReturnAuthRequired as auth_error:
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAccessDenied as access_denied:
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.READ_NOT_PERMITTED
                        )
                    except HookReturnNotFound as not_found:
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                    except HookReturnGattError as gatt_error:
                        self.error(
                            gatt_error.request if gatt_error.request is not None else BleAttOpcode.READ_REQUEST,
                            gatt_error.handle if gatt_error.handle is not None else request.handle,
                            gatt_error.error if gatt_error.error is not None else BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                        )
                else:
                    self.error(
                        BleAttOpcode.WRITE_COMMAND,
                        request.handle,
                        BleAttErrorCode.WRITE_NOT_PERMITTED
                    )

            elif isinstance(attr, ClientCharacteristicConfig):
                # Fixed length, make sure size <= 2.
                if len(request.value) <= 2:
                    attr.value = request.value + attr.value[len(request.value):]

                    # Notify our model
                    if attr.config == 0x0001:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic notification callback
                        charac.set_notification_callback(self.notify)
                        if charac not in self.__subscribed_characs:
                            self.__subscribed_characs.append(charac)

                        self.__model.on_characteristic_subscribed(
                            service,
                            charac,
                            notification=True
                        )
                    elif attr.config == 0x0002:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic indication callback
                        charac.set_indication_callback(self.indicate)
                        if charac not in self.__subscribed_characs:
                            self.__subscribed_characs.append(charac)

                        self.__model.on_characteristic_subscribed(
                            service,
                            charac,
                            indication=True
                        )
                    elif attr.config == 0x0000:
                        charac = attr.characteristic
                        service = self.__model.find_service_by_characteristic_handle(charac.handle)

                        # Unset characteristic indication and notification callbacks
                        charac.set_notification_callback(None)
                        charac.set_indication_callback(None)
                        
                        if charac in self.__subscribed_characs:
                            self.__subscribed_characs.remove(charac)

                        # Notify model
                        self.__model.on_characteristic_unsubscribed(
                            service,
                            charac
                        )
                else:
                    # Wrong length
                    self.error(
                        BleAttOpcode.WRITE_COMMAND,
                        request.handle,
                        BleAttErrorCode.INVALID_ATTR_VALUE_LENGTH
                    )
        except IndexError:
            self.error(
                BleAttOpcode.WRITE_COMMAND,
                request.handle,
                BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )


    def on_prepare_write_request(self, request: GattPrepareWriteRequest):
        """Prepare write request
        """
        try:
            # Retrieve attribute from model
            attr = self.__model.find_object_by_handle(request.handle)

            # Queue request
            if request.handle not in self.__write_queues:
                self.__write_queues[request.handle] = []
            self.__write_queues[request.handle].append(request)

            # Send response
            self.att.prepare_write_response(
                request.handle,
                request.offset,
                request.value
            )

        except IndexError:
            self.error(
                BleAttOpcode.PREPARE_WRITE_REQUEST,
                request.handle,
                BleAttErrorCode.INVALID_HANDLE
            )

    def on_execute_write_request(self, request: GattExecuteWriteRequest):
        """Execute write request
        """
        # Clear all prepared write queues
        if request.flags == 0:
            self.__write_queues = {}
            self.att.execute_write_response()
        elif request.flags == 1:
            # Apply write requests to items
            for handle in self.__write_queues:
                try:
                    # Retrieve attribute from model
                    attr = self.__model.find_object_by_handle(handle)

                    if isinstance(attr, CharacteristicValue):
                        # apply each update
                        for write_req in self.__write_queues[handle]:
                            attr_value = attr.value
                            if write_req.offset > len(attr_value):
                                # Clear queues
                                self.__write_queues = {}
                                
                                # Send error
                                self.error(
                                    BleAttOpcode.EXECUTE_WRITE_REQUEST,
                                    handle,
                                    BleAttErrorCode.INVALID_OFFSET
                                )

                                # Stop now
                                return
                            else:
                                if len(attr_value) >= (write_req.offset + len(write_req.value)):
                                    attr_value = attr_value[:write_req.offset] + write_req.value + attr_value[write_req.offset + len(write_req.value):]
                                else:
                                    attr_value = attr_value[:write_req.offset] + write_req.value
                                attr.value = attr_value
                    else:
                        # Nope, only characteristic values are supported
                        pass

                except IndexError:
                    # Clear write queues
                    self.__write_queues = {}

                    # Send error
                    self.error(
                        BleAttOpcode.EXECUTE_WRITE_REQUEST,
                        request.handle,
                        BleAttErrorCode.INVALID_HANDLE
                    )

                    # Done
                    return

            # Done !
            self.att.execute_write_response()
        else:
            # Unknown flag !
            pass

    def on_read_by_type_request(self, start, end, uuid):
        """Read attribute by type request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.__model.attr_by_type_uuid(UUID(uuid), start, end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:
            
            # Get MTU
            mtu = self.att.local_mtu

            # Get item size (UUID size + 2)
            uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
            item_size = uuid_size + 5
            max_nb_items = int((mtu - 2) / item_size)
            
            # Create our datalist
            datalist = GattAttributeDataList(item_size)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    attr_obj = attrs[handle]
                    if len(attr_obj.uuid.packed) == uuid_size:
                        if isinstance(attrs[handle], Characteristic):
                            datalist.append(
                                GattAttributeValueItem(
                                    handle,
                                    pack(
                                        '<BH',
                                        attr_obj.properties,
                                        attr_obj.value_handle,
                                    ) + attr_obj.uuid.packed
                                )
                            )
                else:
                    break
            
            # Check that our result datalist does contain something
            if len(datalist) > 0:
                # Once datalist created, send answer
                datalist_raw = datalist.to_bytes()
                self.att.read_by_type_response(item_size, datalist_raw)
            else:
                # If not, send an error.
                self.error(
                    BleAttOpcode.READ_BY_TYPE_REQUEST,
                    start,
                    BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                )
        else:
            self.error(
               BleAttOpcode.READ_BY_TYPE_REQUEST,
               start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )


    def on_read_by_group_type_request(self, start, end, uuid):
        """Read by group type request

        List attribute with given type UUID from `start` handle to ̀`end` handle.
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.__model.attr_by_type_uuid(UUID(uuid), start, end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:
            
            # Get MTU
            mtu = self.att.local_mtu

            # Get item size (UUID size + 4)
            uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
            item_size = uuid_size + 4
            max_nb_items = int((mtu - 2) / item_size)
            
            # Create our datalist
            datalist = GattAttributeDataList(item_size)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    end_handle = attrs[handle].end_handle
                    attr_uuid = attrs[handle].uuid
                    if len(attr_uuid.packed) == uuid_size:
                        datalist.append(
                            GattGroupTypeItem(handle, end_handle, attr_uuid.packed)
                        )
                else:
                    break
            
            # Once datalist created, send answer
            datalist_raw = datalist.to_bytes()
            self.att.read_by_group_type_response(item_size, datalist_raw)
        else:
            self.error(
               BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST,
               start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    def on_terminated(self):
        """Connection has been terminated, remove characteristics subscriptions.
        """
        for charac in self.__subscribed_characs:
            charac.set_notification_callback(None)
            charac.set_indication_callback(None)
        self.__subscribed_characs = []


        


        
