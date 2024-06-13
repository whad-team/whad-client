"""GATT Server and Client implementation
"""
import logging

from time import time
from queue import Queue, Empty
from struct import unpack, pack
from threading import Lock

from scapy.layers.bluetooth import ATT_Handle

from whad.ble.exceptions import HookReturnValue, HookReturnAuthentRequired,\
    HookReturnAuthorRequired, HookReturnAccessDenied, HookReturnGattError, \
    HookReturnNotFound, ConnectionLostException
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode, ReadAccess, \
    WriteAccess, Authentication, Authorization, Encryption
from whad.ble.stack.att.exceptions import error_response_to_exc, AttErrorCode
from whad.ble.stack.gatt.message import *
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.profile import GenericProfile, Pairing
from whad.ble.profile.characteristic import Characteristic, CharacteristicDescriptor, ClientCharacteristicConfig, CharacteristicValue
from whad.ble.profile.service import PrimaryService, SecondaryService, IncludeService

from whad.common.stack import Layer, source, alias

logger = logging.getLogger(__name__)

def txlock(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result
    return _wrapper

def proclock(f):
    def _wrapper(self, *args, **kwargs):
        self.procedure_start()
        result = f(self, *args, **kwargs)
        self.procedure_stop()
        return result
    return _wrapper

@alias('gatt')
class GattLayer(Layer):
    '''Gatt client/server base class
    '''

    def configure(self, options):
        '''Configure the GATT layer
        '''
        self.__queue = Queue()
        self.__proc_lock = Lock()
        self.__tx_lock = Lock()
        self.state.terminated = False

        # Dispatch rules
        self.__handlers = {
            GattErrorResponse: self.on_error_response,

            GattFindInfoRequest: self.on_find_info_request,
            GattFindInfoResponse: self.on_find_info_response,

            GattFindByTypeValueRequest: self.on_find_by_type_value_request,
            GattFindByTypeValueResponse: self.on_find_by_type_value_response,

            GattReadByTypeRequest: self.on_read_by_type_request,
            GattReadByTypeResponse: self.on_read_by_type_response,

            GattReadByGroupTypeRequest: self.on_read_by_group_type_request,
            GattReadByGroupTypeResponse: self.on_read_by_group_type_response,

            GattReadRequest: self.on_read_request,
            GattReadResponse: self.on_read_response,

            GattReadBlobRequest: self.on_read_blob_request,
            GattReadBlobResponse: self.on_read_blob_response,

            GattReadMultipleRequest: self.on_read_multiple_request,
            GattReadMultipleResponse: self.on_read_multiple_response,

            GattWriteRequest: self.on_write_request,
            GattWriteCommand: self.on_write_command,
            GattWriteResponse: self.on_write_response,

            GattHandleValueNotification: self.on_handle_value_notification,
            GattHandleValueIndication: self.on_handle_value_indication,

            GattPrepareWriteRequest: self.on_prepare_write_request,
            GattPrepareWriteResponse: self.on_prepare_write_response,

            GattExecuteWriteRequest: self.on_execute_write_request,
            GattExecuteWriteResponse: self.on_execute_write_response,

        }

    @property
    def att(self):
        return self.get_layer('att')

    @property
    def smp(self):
        return self.get_layer('smp')

    @source('att')
    def on_att_packet(self, packet):
        '''Process ATT packets
        '''
        # Dispatch on the correct handler
        packet_type = type(packet)
        if packet_type in self.__handlers:
            self.__handlers[packet_type](packet)
        else:
            logger.error('no GATT handler for packet type %s' % packet_type.__name__)

    def procedure_start(self):
        """
        Lock GATT client or server to avoid a new procedure to be initiated while
        another is actually in progress.
        """
        logger.debug('Start of GATT procedure ...')
        self.__proc_lock.acquire()

    def procedure_stop(self):
        """Unlock GATT client or server to allow other pocedures to be executed.
        """
        logger.debug('End of GATT procedure')
        self.__proc_lock.release()

    def lock_tx(self):
        """Lock GATT client or server to process a single PDU and avoid other PDUs
        to be sent in-between.
        """
        logger.debug('Start handling PDU (tx/rx)')
        self.__tx_lock.acquire()

    def unlock_tx(self):
        """Unlock GATT client or server in order to allow other PDUs to be processed.
        """
        logger.debug('End handling PDU (tx/rx)')
        self.__tx_lock.release()

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
            # Check if connection has been terminated.
            if self.state.terminated:
                logger.debug('Connection lost')
                raise ConnectionLostException(None)
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

    def on_error_response(self, error: GattErrorResponse):
        self.on_gatt_message(error)

    @txlock
    def on_find_info_request(self, packet: GattFindInfoRequest):
        '''ATT Find Information Request callback

        By default, this method generates an ATT Error Response with ATTRIBUTE_NOT_FOUND error.

        :param int start: Start handle value
        :param int end: End handle value
        '''
        logger.debug('[gatt] find_info_request, start:%d, end:%d' %(
            packet.start, packet.end
        ))
        self.error(
            BleAttOpcode.FIND_INFO_REQUEST, packet.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_info_response(self, packet: GattFindInfoResponse):
        '''ATT Find Information Response callback

        :param format: Information data format
        :param handles: List of handles
        '''
        pass

    @txlock
    def on_find_by_type_value_request(self, request: GattFindByTypeValueRequest):
        """ATT Find By Type Value Request callback

        :param GattFindByTypeValueRequest request: Request
        """
        logger.debug('[gatt] FindByTypeValueRequest, start: %d, type: %s' % (request.start, request.type))
        self.error(
            BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST, request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_find_by_type_value_response(self, response: GattFindByTypeValueResponse):
        """ATT Find By Type Value Response callback

        :param GattFindByTypeValueResponse response: Response message
        """
        pass

    @txlock
    def on_read_by_type_request(self, request: GattReadByTypeRequest):
        """ATT Read By Type Request callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid: Type UUID
        """
        self.error(
            BleAttOpcode.READ_BY_TYPE_REQUEST, request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )

    def on_read_by_type_response(self, response):
        """ATT Read By Type Response callback

        :param GattReadByTypeResponse response: Response
        """
        pass

    @txlock
    def on_read_by_group_type_request(self, request: GattReadByGroupTypeRequest):
        """ATT Read By Group Type Request callback

        :param int start: Start handle value
        :param int end: End handle value
        :param uuid: Type UUID
        """
        self.error(
            BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST, request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        )


    def on_read_by_group_type_response(self, response):
        """ATT Read By Group Type Response callback

        :param int item_length: Item length
        :param data: List of items
        """
        pass

    @txlock
    def on_read_request(self, request: GattReadRequest):
        """ATT Read Request callback

        :param int handle: Attribute handle
        """
        self.error(
            BleAttOpcode.READ_REQUEST, request.handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_response(self, response: GattReadResponse):
        """ATT Read Response callback

        :param value: Attribute value
        """
        pass

    @txlock
    def on_read_blob_request(self, request: GattReadBlobRequest):
        """ATT Read Blob Request callback

        :param int handle: Attribute handle
        :param int offset: Offset of the first byte of data to read
        """
        self.error(
            BleAttOpcode.READ_BLOB_REQUEST, request.handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_blob_response(self, response: GattReadBlobResponse):
        """ATT Read Blob Response callback

        :param value: Attribute value
        """
        pass

    @txlock
    def on_read_multiple_request(self, request: GattReadMultipleRequest):
        """ATT Read Multiple Request callback

        :param handles: List of handles
        """
        self.error(
            BleAttOpcode.READ_MULTIPLE_REQUEST, request.handles[0], BleAttErrorCode.INVALID_HANDLE
        )

    def on_read_multiple_response(self, response: GattReadMultipleResponse):
        """ATT Read Multiple Response callback

        :param values: Multiple Attribute values
        """
        pass


    @txlock
    def on_write_request(self, request: GattWriteRequest):
        """ATT Write Request callback

        :param int handle: Attribute handle
        :param data: Attribute value
        """
        self.error(
            BleAttOpcode.WRITE_REQUEST, request.handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_write_response(self, response):
        """ATT Write Response callback
        """
        pass

    @txlock
    def on_write_command(self, request: GattWriteCommand):
        """ATT Write Command callback

        :param int handle: Attribute handle
        :param data: Attribute data
        """
        self.error(
            BleAttOpcode.WRITE_COMMAND, request.handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_handle_value_notification(self, notification: GattHandleValueNotification):
        """ATT Handle Value Notification

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        pass

    @txlock
    def on_handle_value_indication(self, indication: GattHandleValueIndication):
        """ATT Handle Value Indication

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        self.att.handle_value_confirmation()

    @txlock
    def on_prepare_write_request(self, request: GattPrepareWriteRequest):
        """ATT Prepare Write request callback

        :param int handle: Attribute handle
        :param int offset: Data offset
        :param data: Attribute data
        """
        self.error(
            BleAttOpcode.PREPARE_WRITE_REQUEST, request.handle, BleAttErrorCode.INVALID_HANDLE
        )

    def on_prepare_write_response(self, response: GattPrepareWriteResponse):
        """ATT Prepare Write Response Callback

        :param int handle: Attribute handle
        :param int offset: Data offset
        :param data: Attribute data
        """
        pass

    def on_execute_write_request(self, request: GattExecuteWriteRequest):
        """ATT Execute Write Request callback

        :param int flags: Flags
        """
        pass

    def on_execute_write_response(self, response: GattExecuteWriteResponse):
        """ATT Execute Write Response callback
        """
        pass



class GattClient(GattLayer):

    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        self.__model = None
        self.__notification_callbacks = {}

    def configure(self, options):
        '''Configure GATT client.
        '''
        super().configure(options)


    @property
    def model(self):
        return self.__model

    def set_model(self, model):
        '''Set the underlying GATT profile.
        '''
        if isinstance(model, GenericProfile):
            self.__model = model

    def set_client_model(self, model):
        '''This method is used with GattClientServer to specify the GATT
        client device profile.
        '''
        if isinstance(model, GenericProfile):
            self.__model = model


    ###################################
    # Supported response handlers
    ###################################

    def on_read_by_group_type_response(self, response: GattReadByGroupTypeResponse):
        """ATT Read By Group Type Response callback
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

    def on_read_by_type_response(self, response: GattReadByTypeResponse):
        """ATT Read By Type Response callback

        :param GattReadByTypeResponse response: Response
        """
        self.on_gatt_message(response)

    def on_read_blob_response(self, response: GattReadBlobResponse):
        """ATT Read Blob Response callback

        :param value: Attribute value
        """
        self.on_gatt_message(response)

    def on_write_response(self, response):
        """ATT Write Response callback
        """
        self.on_gatt_message(response)

    def on_prepare_write_response(self, response):
        """ATT Prepare Write Response Callback

        :param GattPrepareWriteResponse response: Response message
        """
        self.on_gatt_message(response)

    def on_execute_write_response(self, response):
        """ATT Execute Write Response Callback

        :param GattExecuteWriteResponse response: Response message
        """
        self.on_gatt_message(response)

    def on_find_by_type_value_response(self, response: GattFindByTypeValueResponse):
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

    @txlock
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

    def on_exch_mtu_response(self, response):
        """ATT MTU exchange response

        :param GattExchangeMtuResponse response: response from remote device
        """
        self.on_gatt_message(response)


    ###################################
    # GATT procedures
    ###################################

    def register_notification_callback(self, handle, cb):
        self.__notification_callbacks[handle] = cb

    def unregister_notification_callback(self, handle):
        if handle in self.__notification_callbacks:
            del self.__notification_callbacks[handle]

    def clear_notification_callbacks(self):
        """Clear all notification callbacks.
        """
        self.__notification_callbacks = {}

    @proclock
    def discover_primary_service_by_uuid(self, uuid):
        """Discover a primary service by its UUID.

        :param UUID uuid: Service UUID
        :return: Service if service has been found, None otherwise
        """
        # Send FindByTypeValueRequest
        self.lock_tx()
        self.att.find_by_type_value_request(
            1,
            0xFFFF,
            0x2800,
            uuid.packed
        )
        self.unlock_tx()

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

    @proclock
    def discover_primary_services(self):
        """Discover remote Primary Services.

        This function will yield every discovered primary service.
        """
        # List primary services handles
        handle = 1
        while True:
            # Send a Read By Group Type Request
            self.lock_tx()
            self.att.read_by_group_type_request(
                handle,
                0xFFFF,
                0x2800
            )
            self.unlock_tx()

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

    @proclock
    def discover_secondary_services(self):
        """Discover remote Secondary Services.
        """
        # List primary services handles
        handle = 1
        while True:
            # Send a Read By Group Type Request
            self.lock_tx()
            self.att.read_by_group_type_request(
                handle,
                0xFFFF,
                0x2801
            )
            self.unlock_tx()

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

    @proclock
    def discover_characteristics(self, service):
        """
        Discover service characteristics
        """
        logger.debug('discover characteristics for service %s' % service.uuid)
        logger.debug('discover characteristics from handle %d to %d' % (
            service.handle, service.end_handle
        ))
        if isinstance(service, PrimaryService):
            handle = service.handle
        else:
            return

        while handle <= service.end_handle:
            logger.debug('service end handle is: %d' % service.end_handle)
            self.lock_tx()
            self.att.read_by_type_request(
                handle,
                service.end_handle,
                0x2803
            )
            self.unlock_tx()

            msg = self.wait_for_message(GattReadByTypeResponse)
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
                    handle = charac.handle+2
                    logger.debug('found characteristic %s with handle %d' % (charac_uuid, charac_value_handle))
                    yield charac

            elif isinstance(msg, GattErrorResponse):
                if msg.reason == AttErrorCode.ATTR_NOT_FOUND:
                    break
                else:
                    error_response_to_exc(msg.reason, msg.request, msg.handle)

    @proclock
    def discover_characteristic_descriptors(self, characteristic):
        """Find characteristic descriptor
        """
        if isinstance(characteristic, Characteristic):
            handle = characteristic.value_handle + 1
            end_handle = self.__model.find_characteristic_end_handle(characteristic.handle)
            while handle <= end_handle:
                self.lock_tx()
                self.att.find_info_request(
                    handle,
                    end_handle
                )
                self.unlock_tx()

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

    @proclock
    def read(self, handle):
        """Read a characteristic or a descriptor.

        :param int handle: Handle of the attribute to read (descriptor or characteristic)
        """
        self.lock_tx()
        self.att.read_request(gatt_handle=handle)
        self.unlock_tx()

        msg = self.wait_for_message(GattReadResponse)
        if isinstance(msg, GattReadResponse):
            return msg.value
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    @proclock
    def read_blob(self, handle, offset=0):
        """Read a characteristic or a descriptor starting from `offset`.

        :param int handle: Handle of the characteristic value or descriptor to read.
        :param int offset: Start reading from this offset value (default: 0)
        """
        self.lock_tx()
        self.att.read_blob_request(handle, offset)
        self.unlock_tx()

        msg = self.wait_for_message(GattReadBlobResponse)
        if isinstance(msg, GattReadBlobResponse):
            return msg.value
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    @proclock
    def read_long(self, handle):
        """Read a long characteristic or descriptor

        :param int handle: Handle of the attribute to read (descriptor or characteristic)
        """
        local_mtu = self.get_layer('l2cap').get_local_mtu()

        value=b''
        offset=0
        while True:
            # Send a ReadBlob request
            self.lock_tx()
            self.att.read_blob_request(handle, offset)
            self.unlock_tx()

            msg = self.wait_for_message(GattReadBlobResponse)
            if isinstance(msg, GattReadBlobResponse):
                if len(msg.value) < (local_mtu - 1):
                    value += msg.value
                    break
                else:
                    value += msg.value
                    offset += len(msg.value)
            elif isinstance(msg, GattErrorResponse):
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)
        return value

    @proclock
    def write(self, handle, value):
        """Write data to a characteristic or a descriptor

        :param int handle: Target characteristic or descriptor handle
        :param bytes value: Data to write
        """
        local_mtu = self.get_layer('l2cap').get_local_mtu()

        # Check if data to write is longer than MTU
        if len(value) > (local_mtu - 3):
            # Redirect to write_long_nolock()
            return self.write_long_nolock(handle, value)
        else:
            # If data can be sent in a single write request, just send it :)
            self.lock_tx()
            self.att.write_request(
                handle,
                value
            )
            self.unlock_tx()

            msg = self.wait_for_message(GattWriteResponse)
            if isinstance(msg, GattWriteResponse):
                return True
            elif isinstance(msg, GattErrorResponse):
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    @proclock
    def write_command(self, handle, value):
        """Write data to a characteristic or a descriptor, do not expect an answer.

        :param int handle: Target characteristic or descriptor handle
        :param bytes value: Data to write
        """
        self.lock_tx()
        self.att.write_command(
            handle,
            value
        )
        self.unlock_tx()

        # Write command does not cause the GATT server to return a response.
        return True

    @proclock
    def write_long(self, handle, value):
        """Write a long value into a characteristic

        This function wraps a call to `write_long_nolock()` to ensure this procedure
        is not started while another GATT procedure is in progress.
        """
        return self.write_long_nolock(handle, value)

    def write_long_nolock(self, handle, value):
        """Write long data (size > ATT_MTU-2) to a characteristic value.

        This method uses Prepared Write requests as described in Vol 3, Part G,
        section 4.9.5.

        :param int handle: Target characteristic value handle
        :param bytes value: Data to write
        """
        # We need to determine how many prepared write requests we should issue
        # to the target device
        data_len = len(value)
        local_mtu = self.get_layer('l2cap').get_local_mtu()

        nb_chunks = int(data_len / (local_mtu - 5))
        if nb_chunks % (local_mtu - 5) > 0:
            nb_chunks += 1
        chunk_size = local_mtu - 5

        # Send prepared write requests
        offset = 0
        for i in range(nb_chunks):
            self.lock_tx()
            self.att.prepare_write_request(handle, offset, value[offset:offset + chunk_size])
            self.unlock_tx()

            msg = self.wait_for_message(GattPrepareWriteResponse)
            if isinstance(msg, GattPrepareWriteResponse):
                if msg.value is not None:
                    offset += len(msg.value)
                else:
                    break
            elif isinstance(msg, GattErrorResponse):
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)

        # Execute write request
        self.lock_tx()
        self.att.execute_write_request(1)
        self.unlock_tx()

        msg = self.wait_for_message(GattExecuteWriteResponse)
        if isinstance(msg, GattExecuteWriteResponse):
            return True
        elif isinstance(msg, GattErrorResponse):
            raise error_response_to_exc(msg.reason, msg.request, msg.handle)

    @proclock
    def read_characteristic_by_uuid(self, uuid, start=1, end=0xFFFF):
        """Read a characteristic given its UUID if its handle is comprised in a given range.

        :param UUID uuid: Characteristic UUID
        :param int start: Start handle value
        :param int end: End handle value
        """
        if uuid.type == UUID.TYPE_16:
            self.att.read_by_type_request(start, end, uuid.value())
        elif uuid.type == UUID.TYPE_128:
            # Required by scapy
            uuid1 = unpack('<Q', uuid.packed[:8])[0]
            uuid2 = unpack('<Q', uuid.packed[8:])[0]

            self.lock_tx()
            self.att.read_by_type_request_128bit(start, end, uuid1, uuid2)
            self.unlock_tx()

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

    @proclock
    def set_mtu(self, mtu):
        '''Set (G)ATT client MTU (must be >= ATT_MTU, i.e. 23).

        This method is exposed in GattClient but really interact with the underlying
        ATT layer, and checks if we receive an answer from the remote device.

        :param int mtu: ATT MTU to use
        :return int: remote device MTU
        '''
        if mtu >= 23:
            self.lock_tx()
            self.att.exch_mtu_request(mtu)
            self.unlock_tx()

            msg = self.wait_for_message(GattExchangeMtuResponse)
            if isinstance(msg, GattExchangeMtuResponse):
                return msg.mtu
            elif isinstance(msg, GattErrorResponse):
                raise error_response_to_exc(msg.reason, msg.request, msg.handle)
        else:
            return None

    def services(self):
        return self.__model.services()

    def on_terminated(self):
        # Process termination.
        #super().on_terminated()

        # Remove all notification/indication callbacks
        self.clear_notification_callbacks()


class GattServer(GattLayer):
    """
    BLE GATT server
    """

    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        self.__server_model = None

        # Prepared write queues
        self.__write_queues = {}

        # Subscribed characteristics
        self.__subscribed_characs = []

    @property
    def server_model(self):
        """Retrieve the current server model
        """
        return self.__server_model

    def set_model(self, model):
        '''Set the GATT server underlying profile.
        '''
        self.__server_model = model

    def set_server_model(self, model):
        '''This method is used with GattClientServer to specify the GATT
        server profile.
        '''
        # Note: redundant with set_server_model
        self.__server_model = model

    def configure(self, options):
        '''Configure GATT client.
        '''
        super().configure(options)


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
            local_mtu = self.get_layer('l2cap').get_local_mtu()

            # Call model callback
            service = self.server_model.find_service_by_characteristic_handle(characteristic.handle)
            self.server_model.on_notification(
                service,
                characteristic,
                characteristic.value[:local_mtu-3]
            )

            # Send notification
            self.att.handle_value_notification(
                characteristic.value_handle,
                characteristic.value[:local_mtu-3]
            )
        except HookReturnValue as value_override:
            # Return overriden value
            self.att.handle_value_notification(
                characteristic.value_handle,
                value_override.value[:local_mtu-3]
            )

    @proclock
    def indicate(self, characteristic):
        """Sends an indication to a GATT client for a given characteristic.

        :param Characteristic characteristic: Characteristic to notify the GATT client about.
        """
        try:
            local_mtu = self.get_layer('l2cap').get_local_mtu()

            # Call model callback
            service = self.server_model.find_service_by_characteristic_handle(characteristic.handle)
            self.server_model.on_indication(
                service,
                characteristic,
                characteristic.value[:local_mtu-3]
            )

            # Send notification
            self.att.handle_value_indication(
                characteristic.value_handle,
                characteristic.value[:local_mtu-3]
            )
        except HookReturnValue as value_override:
            # Return overriden value
            self.att.handle_value_indication(
                characteristic.value_handle,
                value_override.value[:local_mtu-3]
            )

    @txlock
    def on_find_info_request(self, request):
        """Find information request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

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

    @txlock
    def on_find_by_type_value_request(self, request: GattFindByTypeValueRequest):
        """ATT Find By Type Value Request callback

        :param GattFindByTypeValueRequest request: Request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()
        print(attrs_handles)
        print(request.value)

        # Loop on attributes and return the attributes with a value that matches the request value
        matching_attrs = []
        for handle in attrs_handles:
            # Retrieve attribute based on handle
            attr = attrs[handle]

            # If attribute is a characteristic value or a descriptor, we make sure the characteristic
            # is readable before matching its value with the request value
            if isinstance(attr, CharacteristicValue) or isinstance(attr, CharacteristicDescriptor):
                if attr.characteristic.readable():
                    # Find characteristic end handle
                    if attr.value == request.value:
                        matching_attrs.append((handle, attr.characteristic.end_handle))
            else:
                # PrimaryService and SecondaryService are grouping types
                if isinstance(attr, PrimaryService) or isinstance(attr, SecondaryService):
                    if attr.value == request.value:
                        matching_attrs.append((handle, attr.end_handle))
                else:
                    if attr.value == request.value:
                        matching_attrs.append((handle, handle))

        # If we have found at least one attribute that matches the request, return a
        # FindByTypeValueResponse PDU
        if len(matching_attrs) > 0:
            # Build the response
            mtu = self.get_layer('l2cap').get_local_mtu()
            max_nb_items = int((mtu - 1) / 4)

            # Create our datalist
            handles_list = []

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(matching_attrs):
                    handle, end_handle = matching_attrs[i]
                    attr_obj = attrs[handle]
                    handles_list.append(
                        ATT_Handle(
                            handle=handle,
                            value=end_handle
                        )
                    )
                else:
                    break

            # Once datalist created, send answer
            self.att.find_by_type_value_response(handles_list)
        else:
            # Attribute not found
            self.error(
               BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )


    @txlock
    def on_read_request(self, request):
        """Read attribute value (if any)

        :param int handle: Characteristic or descriptor handle
        """
        try:
            local_mtu = self.get_layer('l2cap').get_local_mtu()

            # Search attribute by handle and send respons
            attr = self.server_model.find_object_by_handle(request.handle)

            # Ensure attribute is a readable characteristic value or a descriptor
            if isinstance(attr, CharacteristicValue):

                # Check characteristic is readable
                charac = self.server_model.find_object_by_handle(request.handle - 1)

                conn_handle = self.get_layer('l2cap').get_conn_handle()
                if charac.check_security_property(ReadAccess, Authentication):
                    print("[i] authentication required for read access !")
                    if not self.get_layer('ll').state.is_authenticated(conn_handle):
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                        return
                if charac.check_security_property(ReadAccess, Encryption):
                    print("[i] encryption required for read access !")
                    if not self.get_layer('ll').state.is_encrypted(conn_handle):
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_ENCRYPTION
                        )
                        return
                if charac.check_security_property(ReadAccess, Authorization):
                    print("[i] authorization required for read access !")
                    # TODO: not supported for now
                    self.error(
                        BleAttOpcode.READ_REQUEST,
                        request.handle,
                        BleAttErrorCode.INSUFFICIENT_AUTHOR
                    )
                    return
                if charac.readable():
                    try:
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)
                        self.server_model.on_characteristic_read(
                            service,
                            charac,
                            0,
                            local_mtu - 1
                        )

                        # Make sure the returned value matches the boundaries
                        value = charac.value[:local_mtu - 1]

                        self.att.read_response(
                            value
                        )
                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        value = force_value.value[:local_mtu - 1]

                        self.att.read_response(
                            value
                        )
                    except HookReturnAuthentRequired as authent_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAuthorRequired as author_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHOR
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
            elif isinstance(attr, Characteristic):
                # Return characteristic value
                self.att.read_response(
                    attr.payload()
                )
            elif isinstance(attr, PrimaryService):
                # Return primary service value
                self.att.read_response(
                    attr.payload()
                )
            elif isinstance(attr, CharacteristicDescriptor):
                # Make sure the returned value matches the boundaries
                self.att.read_response(
                    attr.value[:local_mtu - 1]
                )

        except IndexError as e:
            self.error(
                BleAttOpcode.READ_REQUEST,
                request.handle,
                BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    @txlock
    def on_read_blob_request(self, request: GattReadBlobRequest):
        """Read blob request
        """
        try:
            local_mtu = self.get_layer('l2cap').get_local_mtu()

            # Search attribute by handle and send response
            attr = self.server_model.find_object_by_handle(request.handle)

            if request.offset < len(attr.value):

                # If attribute is a characteristic, make sure it is readable
                # before returning a value.
                if isinstance(attr, CharacteristicValue):
                    try:
                        charac = self.server_model.find_object_by_handle(request.handle - 1)
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        conn_handle = self.get_layer('l2cap').get_conn_handle()
                        if charac.check_security_property(ReadAccess, Authentication):
                            print("[i] authentication required for read access !")
                            if not self.get_layer('ll').state.is_authenticated(conn_handle):
                                self.error(
                                    BleAttOpcode.READ_BLOB_REQUEST,
                                    request.handle,
                                    BleAttErrorCode.INSUFFICIENT_AUTHENT
                                )
                                return
                        if charac.check_security_property(ReadAccess, Encryption):
                            print("[i] encryption required for read access !")
                            if not self.get_layer('ll').state.is_encrypted(conn_handle):
                                self.error(
                                    BleAttOpcode.READ_BLOB_REQUEST,
                                    request.handle,
                                    BleAttErrorCode.INSUFFICIENT_ENCRYPTION
                                )
                                return
                        if charac.check_security_property(ReadAccess, Authorization):
                            print("[i] authorization required for read access !")
                            # TODO: not supported for now
                            self.error(
                                BleAttOpcode.READ_BLOB_REQUEST,
                                request.handle,
                                BleAttErrorCode.INSUFFICIENT_AUTHOR
                            )
                            return
                        if not charac.readable():
                            self.error(
                                BleAttOpcode.READ_BLOB_REQUEST,
                                request.handle,
                                BleAttErrorCode.READ_NOT_PERMITTED
                            )
                            return

                        # Call our characteristic read hook
                        self.server_model.on_characteristic_read(
                            service,
                            charac,
                            request.offset,
                            local_mtu - 1
                        )

                        # Make sure the returned value matches the boundaries
                        value = charac.value[request.offset:request.offset + local_mtu - 1]

                        self.att.read_blob_response(
                            value
                        )

                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        value = force_value.value[:local_mtu - 1]

                        self.att.read_blob_response(
                            value
                        )
                    except HookReturnAuthentRequired as authent_error:
                        self.error(
                            BleAttOpcode.READ_BLOB_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAuthorRequired as author_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHOR
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
                        attr.value[request.offset:request.offset + local_mtu - 1]
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

    @txlock
    def on_write_request(self, request):
        """Write request for characteristic or descriptor value
        """
        try:
            # Retrieve attribute from model
            attr = self.server_model.find_object_by_handle(request.handle)
            if isinstance(attr, CharacteristicValue):
                # Check the corresponding characteristic is writeable
                charac = self.server_model.find_object_by_handle(request.handle - 1)

                conn_handle = self.get_layer('l2cap').get_conn_handle()
                if charac.check_security_property(WriteAccess, Authentication):
                    print("[i] authentication required for write access !")
                    if not self.get_layer('ll').state.is_authenticated(conn_handle):
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                        return
                if charac.check_security_property(WriteAccess, Encryption):
                    print("[i] encryption required for write access !")
                    if not self.get_layer('ll').state.is_encrypted(conn_handle):
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_ENCRYPTION
                        )
                        return
                if charac.check_security_property(WriteAccess, Authorization):
                    print("[i] authorization required for write access !")
                    # TODO: not supported for now
                    self.error(
                        BleAttOpcode.WRITE_REQUEST,
                        request.handle,
                        BleAttErrorCode.INSUFFICIENT_AUTHOR
                    )
                    return
                if charac.writeable():
                    # Retrieve corresponding service info
                    service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                    try:
                        # Trigger our write hook
                        self.server_model.on_characteristic_write(
                            service,
                            charac,
                            0,
                            request.value,
                            False
                        )

                        # Update attribute value
                        attr.value = request.value
                        self.att.write_response()

                        # Trigger our written hook (after charac has been written)
                        value =  self.server_model.on_characteristic_written(
                            service,
                            charac,
                            0,
                            attr.value,
                            True
                        )

                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        attr.value = force_value.value
                        self.att.write_response()

                        # Trigger our written hook (after charac has been written)
                        value =  self.server_model.on_characteristic_written(
                            service,
                            charac,
                            0,
                            attr.value,
                            True
                        )

                    except HookReturnAuthentRequired as authent_error:
                        self.error(
                            BleAttOpcode.WRITE_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAuthorRequired as author_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHOR
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
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic notification callback
                        charac.set_notification_callback(self.notify)

                        self.server_model.on_characteristic_subscribed(
                            service,
                            charac,
                            notification=True
                        )
                    elif attr.config == 0x0002:
                        charac = attr.characteristic
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic indication callback
                        charac.set_indication_callback(self.indicate)

                        self.server_model.on_characteristic_subscribed(
                            service,
                            charac,
                            indication=True
                        )
                    elif attr.config == 0x0000:
                        charac = attr.characteristic
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Unset characteristic indication and notification callbacks
                        charac.set_notification_callback(None)
                        charac.set_indication_callback(None)

                        # Notify model
                        self.server_model.on_characteristic_unsubscribed(
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

    @txlock
    def on_write_command(self, request):
        """Write command (without response)
        """
        try:
            # Retrieve attribute from model
            attr = self.server_model.find_object_by_handle(request.handle)
            if isinstance(attr, CharacteristicValue):
                # Check the corresponding characteristic is writeable
                charac = self.server_model.find_object_by_handle(request.handle - 1)

                conn_handle = self.get_layer('l2cap').get_conn_handle()
                if charac.check_security_property(WriteAccess, Authentication):
                    print("[i] authentication required for write access !")
                    if not self.get_layer('ll').state.is_authenticated(conn_handle):
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                        return
                if charac.check_security_property(WriteAccess, Encryption):
                    print("[i] encryption required for write access !")
                    if not self.get_layer('ll').state.is_encrypted(conn_handle):
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_ENCRYPTION
                        )
                        return
                if charac.check_security_property(WriteAccess, Authorization):
                    print("[i] authorization required for write access !")
                    # TODO: not supported for now
                    self.error(
                        BleAttOpcode.WRITE_COMMAND,
                        request.handle,
                        BleAttErrorCode.INSUFFICIENT_AUTHOR
                    )
                    return
                if charac.writeable():
                    # Retrieve corresponding service info
                    service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                    try:
                        # Trigger our write hook
                        value =  self.server_model.on_characteristic_write(
                            service,
                            charac,
                            0,
                            request.value,
                            True
                        )

                        # Update attribute value
                        attr.value = request.value

                        # Trigger our written hook (after charac has been written)
                        value =  self.server_model.on_characteristic_written(
                            service,
                            charac,
                            0,
                            attr.value,
                            True
                        )

                    except HookReturnValue as force_value:
                        # Make sure the returned value matches the boundaries
                        attr.value = force_value.value

                        # Trigger our written hook (after charac has been written)
                        value =  self.server_model.on_characteristic_written(
                            service,
                            charac,
                            0,
                            attr.value,
                            True
                        )

                    except HookReturnAuthentRequired as authent_error:
                        self.error(
                            BleAttOpcode.WRITE_COMMAND,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHENT
                        )
                    except HookReturnAuthorRequired as author_error:
                        self.error(
                            BleAttOpcode.READ_REQUEST,
                            request.handle,
                            BleAttErrorCode.INSUFFICIENT_AUTHOR
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
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic notification callback
                        charac.set_notification_callback(self.notify)
                        if charac not in self.__subscribed_characs:
                            self.__subscribed_characs.append(charac)

                        self.server_model.on_characteristic_subscribed(
                            service,
                            charac,
                            notification=True
                        )
                    elif attr.config == 0x0002:
                        charac = attr.characteristic
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Set characteristic indication callback
                        charac.set_indication_callback(self.indicate)
                        if charac not in self.__subscribed_characs:
                            self.__subscribed_characs.append(charac)

                        self.server_model.on_characteristic_subscribed(
                            service,
                            charac,
                            indication=True
                        )
                    elif attr.config == 0x0000:
                        charac = attr.characteristic
                        service = self.server_model.find_service_by_characteristic_handle(charac.handle)

                        # Unset characteristic indication and notification callbacks
                        charac.set_notification_callback(None)
                        charac.set_indication_callback(None)

                        if charac in self.__subscribed_characs:
                            self.__subscribed_characs.remove(charac)

                        # Notify model
                        self.server_model.on_characteristic_unsubscribed(
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

    @txlock
    def on_prepare_write_request(self, request: GattPrepareWriteRequest):
        """Prepare write request
        """
        try:
            # Retrieve attribute from model
            attr = self.server_model.find_object_by_handle(request.handle)

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

    @txlock
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
                    attr = self.server_model.find_object_by_handle(handle)

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

    @txlock
    def on_read_by_type_request(self, request: GattReadByTypeRequest):
        """Read attribute by type request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.attr_by_type_uuid(UUID(request.type), request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

            # If client is looking for characteristic declaration,
            # we compute the correct item size and maximum number
            # of items we can put in a response PDU
            #
            # In the case of a characteristic declaration, UUID could
            # be 16-bit or 128-bit long so we shall only put in the same
            # answer characteristics with same size UUIDs.

            if UUID(request.type) == UUID(0x2803):

                # Get item size (UUID size + 2)
                uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
                item_size = uuid_size + 5
                max_nb_items = int((mtu - 2) / item_size)

                # Create our datalist
                datalist = GattAttributeDataList(item_size)
            elif UUID(request.type) == UUID(0x2802):

                # If client is looking for included services,
                # we compute the correct item size and maximum number
                # of items we can put in a response PDU
                #
                # In the case of an included service declaration, UUID could
                # be 16-bit or 128-bit long so we shall only put in the same
                # answer characteristics with same size UUIDs.

                # Get item size
                uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
                item_size = uuid_size + 6
                max_nb_items = int((mtu - 2) / item_size)

                # Create our datalist
                datalist = GattAttributeDataList(item_size)
            else:
                max_nb_items = 0
                datalist = GattAttributeDataList(0)

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
                        elif isinstance(attrs[handle], IncludeService):
                            if attrs[handle].service_uuid.type == UUID.TYPE_16:
                                datalist.append(
                                    GattAttributeValueItem(
                                        handle,
                                        pack(
                                            '<HH',
                                            attr_obj.service_start_handle,
                                            attr_obj.service_end_handle,
                                        ) + attr_obj.service_uuid.packed
                                    )
                                )
                            else:
                                datalist.append(
                                    GattAttributeValueItem(
                                        handle,
                                        pack(
                                            '<HH',
                                            attr_obj.service_start_handle,
                                            attr_obj.service_end_handle,
                                        )
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
                    request.start,
                    BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                )
        else:
            self.error(
               BleAttOpcode.READ_BY_TYPE_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    @txlock
    def on_read_by_group_type_request(self, request: GattReadByGroupTypeRequest):
        """Read by group type request

        List attribute with given type UUID from `start` handle to ̀`end` handle.
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.attr_by_type_uuid(UUID(request.type), request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

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
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    def on_terminated(self):
        """Connection has been terminated, remove characteristics subscriptions.
        """
        # Unsubscribe from everything and remove callbacks again
        for charac in self.__subscribed_characs:
            charac.set_notification_callback(None)
            charac.set_indication_callback(None)
        self.__subscribed_characs = []

    def pairing(self, pairing=None):
        pairing_parameters = Pairing()
        if pairing is None:
            pairing_parameters = self.server_model.get_pairing_parameters()
        elif isinstance(pairing, Pairing):
            pairing_parameters = pairing

        self.smp.request_pairing(pairing=pairing_parameters)

class GattClientServer(GattServer, GattClient):

    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
