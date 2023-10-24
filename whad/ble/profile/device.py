"""
Bluetooth Low Energy Peripheral abstraction
===========================================

This module provides the PeripheralDevice class used to wrap all GATT operations
for a given connected device. This class wraps all the following operations:

* service and characteristics discovery
* ATT MTU exchange
* characteristic and descriptor read
* characteristic and descriptor write

For instance, a `Central` object can be used to initiate a BLE connection to a
target, and will return a `PeripheralDevice` object, as shown below::

    central = Central(...)
    target = central.connect('00:11:22:33:44:55')

One can then use this object to discover all the services and characteristics::

    target.discover()

And look for a specific characteristic and read it::

    device_name = target.get_characteristic(UUID('1800'), UUID('2A00'))
    if device_name is not None:
        print('Device name is {}'.format(device_name.read()))

It is also possible to write to a characteristic (if writeable)::

    device_name.value = b'MyNewDeviceName'

"""
import logging

from whad.ble.profile.service import Service
from whad.ble.profile.characteristic import CharacteristicDescriptor, \
    CharacteristicProperties, Characteristic, CharacteristicValue
from whad.ble.profile import GenericProfile
from whad.ble.stack.att.constants import BleAttProperties
from whad.ble.profile.attribute import UUID

from struct import unpack
from time import sleep

logger = logging.getLogger(__name__)

class PeripheralCharacteristicDescriptor:
    """Wrapper for a peripheral characteristic descriptor.
    """

    def __init__(self, descriptor, gatt):
        """Initialize a PeripheralCharacteristicDescriptor.

        :param CharacteristicDescriptor descriptor: Descriptor to wrap.
        :param GattClient gatt: GATT client to use for GATT operations (read/write).
        """
        self.__descriptor = descriptor
        self.__gatt = gatt

    @property
    def handle(self):
        """Return this characteristic descriptor handle.

        :return int: Descriptor handle
        """
        return self.__descriptor.handle

    @property
    def type_uuid(self):
        """Return this attribute type UUID.

        :return UUID: Attribute type UUID
        """
        return self.__descriptor.type_uuid

    def read(self):
        """Read descriptor value.

        :return bytes: Descriptor value
        """
        return self.__gatt.read(self.__descriptor.handle)

    def write(self, value, without_response=False):
        """Write descriptor value.

        :param bytes value: Value to write to this descriptor.
        :param bool without_response: If set, use a GATT write command request to write to this descriptor.
        """
        if without_response:
            self.__gatt.write_command(self.__descriptor.handle, value)
        else:
            self.__gatt.write(self.__descriptor.handle, value)

class PeripheralCharacteristicValue:
    """CharacteristicValue wrapper for peripheral devices

    Forward all read/write operations to PeripheralCharacteristic wrapper
    because initially access to characteristic has been implemented there.

    Could be interesting in the future to implement all these operations here
    and to forward from characteristic wrapper to characteristic value wrapper
    because it makes more sense.

    Anyway, this code just works but from an architectural point-of-view is
    a bit crappy.
    """

    def __init__(self, char_value, gatt):
        self.__char_value = char_value
        self.__characteristic = PeripheralCharacteristic(
            char_value.characteristic,
            gatt
        )
        self.__gatt = gatt

    @property
    def handle(self):
        return self.__char_value.handle

    @property
    def characteristic(self):
        return self.__characteristic

    @property
    def value(self):
        """Transparent characteristic read.

        :return bytes: Characteristic value
        """
        return self.__characteristic.read()

    @value.setter
    def value(self, val):
        """Transparent characteristic write.

        :param bytes val: Value to write into this characteristic
        """
        return self.__characteristic.write(val)

    def read(self, offset=0):
        """Read characteristic value
        """
        return self.__characteristic.read(offset=offset)

    def read_long(self):
        return self.__characteristic.read_long()

    def write(self, value, without_response=False):
        return self.__characteristic.write(value, without_response=without_response)


class PeripheralCharacteristic:
    """Characteristic wrapper for peripheral devices

    Instruments gatt to read/write a remote characteristic.
    """
    def __init__(self, characteristic, gatt):
        self.__characteristic = characteristic
        self.__gatt = gatt

    @property
    def value(self):
        """Transparent characteristic read.

        :return bytes: Characteristic value
        """
        return self.read()

    @value.setter
    def value(self, val):
        """Transparent characteristic write.

        :param bytes val: Value to write into this characteristic
        """
        return self.write(val)

    @property
    def uuid(self):
        return self.__characteristic.uuid

    @property
    def type_uuid(self):
        return self.__characteristic.type_uuid

    @property
    def properties(self):
        return self.__characteristic.properties

    @property
    def handle(self):
        return self.__characteristic.handle

    @property
    def end_handle(self):
        return self.__characteristic.end_handle

    @property
    def value_handle(self):
        return self.__characteristic.value_handle

    def can_notify(self):
        return self.__characteristic.can_notify()

    def must_notify(self):
        return self.__characteristic.must_notify()

    def can_indicate(self):
        return self.__characteristic.can_indicate()

    def must_indicate(self):
        return self.__characteristic.must_indicate()

    def read(self, offset=0):
        """Read characteristic value
        """
        if offset == 0:
            return self.__gatt.read(self.__characteristic.value_handle)
        else:
            return self.__gatt.read_blob(self.__characteristic.value_handle, offset)

    def read_long(self):
        """Read long characteristic value
        """
        return self.__gatt.read_long(self.__characteristic.value_handle)

    def write(self, value, without_response=False):
        """Set characteristic value

        If characteristic is only writeable without response, use a write command
        rather than a write request. Otherwise, use a write request. If a characteristic
        has both write and write without response properties, `without_response` must be
        set to True to use a write command.
        """
        # If characteristic is only writeable without response, force without_response to True.
        access_mask = CharacteristicProperties.WRITE_WITHOUT_RESPONSE | CharacteristicProperties.WRITE
        if (self.__characteristic.properties & access_mask) == CharacteristicProperties.WRITE_WITHOUT_RESPONSE:
            without_response = True

        if isinstance(value, bytes):
            if without_response:
                return self.__gatt.write_command(
                    self.__characteristic.value_handle,
                    value
                )
            else:
                return self.__gatt.write(
                    self.__characteristic.value_handle,
                    value
                )

    def descriptors(self):
        """Return all the descriptors associated with this characteristic.

        This method is a generator and will yield all the descriptors registered
        with this characteristic.
        """
        for desc in self.__characteristic.descriptors():
            yield PeripheralCharacteristicDescriptor(
                desc,
                self.__gatt
            )

    def get_descriptor(self, type_uuid):
        """Get descriptor of a given type.

        :param UUID type_uuid: Descriptor type UUID
        :return PeripheralCharacteristicDescriptor: Return descriptor if found, `None` otherwise
        """
        for desc in self.__characteristic.descriptors():
            if desc.type_uuid == type_uuid:
                return PeripheralCharacteristicDescriptor(
                    desc,
                    self.__gatt
                )

    def readable(self):
        """Check if this characteristic is readable.

        :return bool: True if readable, False otherwise.
        """
        return ((self.__characteristic.properties & CharacteristicProperties.READ) != 0)

    def writeable(self):
        """Check if this characteristic is writeable.

        :return bool: True if writeable, False otherwise.
        """
        return (
            ((self.__characteristic.properties & CharacteristicProperties.WRITE) != 0) or
            ((self.__characteristic.properties & CharacteristicProperties.WRITE_WITHOUT_RESPONSE) != 0)
        )

    def subscribe(self, notification=True, indication=False, callback=None):
        """Subscribe for notification/indication.

        :param bool notification: If set, subscribe for notification
        :param bool indication: If set, subscribe for indication (cannot be used when notification is set)
        :param callable callback: Callback function to be called on indication/notification event
        :return bool: True if subscription has successfully been performed, False otherwise.
        """
        if notification:
            # Look for CCCD
            desc = self.get_descriptor(UUID(0x2902))
            if desc is not None:
                # wrap our callback to provide more details about the concerned
                # characteristic
                def wrapped_cb(handle, value, indication=False):
                    callback(
                        self,
                        value,
                        indication=indication
                    )

                # Register our callback
                if callback is not None:
                    self.__gatt.register_notification_callback(
                        self.__characteristic.value_handle,
                        wrapped_cb
                    )

                # Enable notification
                desc.write(bytes([0x01, 0x00]))

                return True
            else:
                print('descriptor not found')
                return False
        elif indication:
            # Look for CCCD
            desc = self.get_descriptor(UUID(0x2902))
            if desc is not None:
                # Register our callback
                if callback is not None:
                    self.__gatt.register_notification_callback(
                        self.__characteristic.value_handle,
                        callback
                    )

                # Enable indication
                desc.write(bytes([0x02, 0x00]))

                return True
            else:
                return False

    def unsubscribe(self):
        """Unsubscribe from this characteristic.
        """
        # Look for CCCD
        desc = self.get_descriptor(UUID(0x2902))

        if desc is not None:
            # Disable notification/indication
            desc.write(bytes([0x00, 0x00]))

            # Unregister our callback
            self.__gatt.unregister_notification_callback(
                self.__characteristic.value_handle
            )
            return True
        else:
            return False


class PeripheralService:
    """Service wrapper for peripheral devices
    """

    def __init__(self, service, gatt):
        self.__service = service
        self.__gatt = gatt

    @property
    def handle(self):
        """Return this service handle.

        :param int: service handle
        """
        return self.__service.handle

    @property
    def end_handle(self):
        """Return this service end handle.

        :return int: end handle
        """
        return self.__service.end_handle

    @property
    def uuid(self):
        """Return this service UUID.

        :param UUID: Service UUID
        """
        return self.__service.uuid

    @property
    def type_uuid(self):
        """Return this service type UUID

        :return UUID: Service type UUID
        """
        return self.__service.type_uuid

    def read_characteristic_by_uuid(self, uuid):
        """Read a characteristic belonging to this service identified by its UUID.

        :param UUID uuid: Characteristic UUID
        :return bytes: Characteristic value
        """
        return self.__gatt.read_characteristic_by_uuid(
            uuid,
            self.__service.handle,
            self.__service.end_handle
        )

    def get_characteristic(self, uuid):
        """Look for a specific characteristic belonging to this service, identified by its UUID.

        :param UUID uuid: Characteristic UUID
        :return PeripheralCharacteristic: Found characteristic if any, `None` otherwise.
        """
        for charac in self.__service.characteristics():
            if charac.uuid == uuid:
                return PeripheralCharacteristic(
                    charac,
                    self.__gatt
                )
        return None

    def characteristics(self):
        """Enumerate this service's characteristics (generator).
        """
        for characteristic in self.__service.characteristics():
            yield PeripheralCharacteristic(
                characteristic,
                self.__gatt
            )

class PeripheralDevice(GenericProfile):
    """GATT client wrapper representing a remote device.

    This class is used to wrap a device model used in a gatt client
    in order to provide easy-to-use methods to access its services,
    characteristics and descriptors.
    """

    def __init__(self,  central, gatt_client, conn_handle, from_json=None):
        """Create a peripheral device from a Central and a GATT client.

        :param  central:        Central instance used to connect to a target device.
        :type   central:        :class:`whad.ble.connector.central.Central`
        :param  gatt_client:    GATT client connected to a target device.
        :type   gatt_client:    :class:`whad.ble.stack.gatt.GattClient`
        :param  conn_handle:    Current connection handle.
        :type   conn_handle:    int
        :param  from_json:      GATT profile (JSON) to be used when instanciating the underlying GattProfile.
        :type   from_json:      str, optional
        """
        self.__gatt = gatt_client
        self.__smp = gatt_client.smp
        self.__ll = gatt_client.get_layer('ll')
        self.__conn_handle = conn_handle
        self.__central = central
        self.__disconnect_cb = None
        super().__init__(from_json=from_json)


    @property
    def conn_handle(self) -> int:
        """Current connection handle.
        """
        return self.__conn_handle


    def start_encryption(self):
        security_database = self.__smp.security_database


        crypto_material = security_database.get(address=self.__central.target_peer)
        conn_handle = self.__smp.get_layer('l2cap').state.conn_handle
        if crypto_material is not None and crypto_material.has_ltk():
            self.__ll.start_encryption(
                conn_handle,
                unpack('>Q', crypto_material.ltk.rand)[0],
                crypto_material.ltk.ediv
            )

    def pairing(self, pairing=None):
        """Trigger a pairing according to provided parameters.
        Default parameters will be used if pairing parameter is None.
        """
        if not self.__smp.initiate_pairing(parameters=pairing):
            return False

        while not self.__smp.is_pairing_done():
            sleep(0.1)
            if self.__smp.is_pairing_failed():
                return False

        self.__smp.reset_state()
        return True

    def set_disconnect_cb(self, callback):
        """Set disconnection callback.

        :param callback:    Callback function to call on disconnection.
        :type   callback:   callable
        """
        self.__disconnect_cb = callback


    def set_mtu(self, mtu: int):
        """Update connection MTU.

        :param  mtu:    ATT MTU to use for this connection.
        :type   mtu:    int
        :return:        Remote device MTU.
        :rtype: int
        """
        return self.__gatt.set_mtu(mtu)


    def disconnect(self):
        """Terminate the connection to this device
        """
        # Ask associated central to disconnect this peripheral device.
        self.__central.disconnect(self.__conn_handle)


    def discover(self):
        """Discovers services, characteristics and descriptors.

        This method must be called before accessing any service or characteristic,
        as it is required to retrieve the corresponding GATT handles.
        """
        # Discover
        self.__gatt.discover()


    def find_service_by_uuid(self, uuid: UUID) -> PeripheralService:
        """Find service by its UUID

        :param  uuid:   Characteristic UUID
        :type   uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:        PeripheralService: An instance of PeripheralService if service has been found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralService`
        """
        service = self.__gatt.discover_primary_service_by_uuid(uuid)
        if service is not None:
            return PeripheralService(
                service,
                self.__gatt
            )
        else:
            return None

    def find_characteristic_by_uuid(self, uuid: UUID):
        """Find characteristic by its UUID

        :param  uuid:   Characteristic UUID
        :type   uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:        PeripheralCharacteristic: An instance of PeripheralCharacteristic if characteristic has been found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralCharacteristic`
        """
        for service in self.services():
            for charac in service.characteristics():
                if charac.uuid == uuid:
                    return PeripheralCharacteristic(
                        charac,
                        self.__gatt
                    )


    def find_object_by_handle(self, handle):
        """Find an existing object (service, attribute, descriptor) based on its handle,
        it known from the underlying GenericProfile.

        :param  handle: Object handle
        :type   handle: int
        :return:        Characteristic, characteristic value or service
        :rtype:         :class:`whad.ble.profile.device.PeripheralCharacteristic`, :class:`whad.ble.profile.device.PeripheralCharacteristicValue`, :class:`whad.ble.profile.device.PeripheralService`
        """
        obj = super().find_object_by_handle(handle)
        if isinstance(obj, Characteristic):
            return PeripheralCharacteristic(
                obj,
                self.__gatt
            )
        elif isinstance(obj, Service):
            return PeripheralService(
                obj,
                self.__gatt
            )
        elif isinstance(obj, CharacteristicValue):
            return PeripheralCharacteristicValue(
                obj,
                self.__gatt
            )

    def get_characteristic(self, service_uuid: UUID, charac_uuid: UUID):
        """Get a PeripheralCharacteristic object representing a characteristic
        defined by the given service UUID and characteristic UUID.

        :param  service_uuid:   Service UUID
        :type   service_uuid:   :class:`whad.ble.profile.attribute.UUID`
        :param  charac_uuid:    Characteristic UUID
        :type   charac_uuid:    :class:`whad.ble.profile.attribute.UUID`
        :return:                PeripheralCharacteristic object on success, None if not found.
        :rtype: :class:`whad.ble.profile.device.PeripheralCharacteristic`
        """
        service = self.get_service(service_uuid)
        if service is not None:
            return service.get_characteristic(charac_uuid)
        return None


    def get_service(self, uuid):
        """Retrieve a PeripheralService object given its UUID.

        :param  uuid:       Service UUID
        :type   uuid:       :class:`whad.ble.profile.attribute.UUID`
        :return:            Corresponding PeripheralService object if found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralService`
        """

        for service in self.services():
            if service.uuid == uuid:
                return PeripheralService(service, self.__gatt)
        return None


    def write(self, handle, value):
        """Perform a write operation on an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor and the
        value to write to it, and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to write on a read-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle to write.
        :type   handle: int
        :param  value:  Bytes to write into this characteristic.
        :type   value:  bytes
        """
        return self.__gatt.write(handle, value)


    def write_command(self, handle, value, without_response=False):
        """Perform a write command operation (no write response will be sent) on
        an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor and the
        value to write to it, and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to write on a read-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle to write.
        :type   handle: int
        :param  value:  Bytes to write into this characteristic.
        :type   value:  bytes
        """
        return self.__gatt.write_command(handle, value)

    def read(self, handle, offset=None, long=False):
        """Perform a read operation on an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor
        and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to read from a write-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle.
        :type   handle: int
        :param  offset: Offset applied when reading data from characteristic or descriptor (default: 0).
        :type   offset: int, optional
        :param  long:   use GATT long read procedure if set to True (default: False)
        :type   long:   bool, optional
        :return:        Content of the characteristic or descriptor.
        :rtype: bytes
        """
        if not long:
            if offset is None:
                return self.__gatt.read(handle)
            else:
                return self.__gatt.read_blob(handle, offset=offset)
        else:
            return self.__gatt.read_long(handle)


    def on_disconnect(self, conn_handle):
        """Disconnection callback

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        logger.debug('PeripheralDevice has disconnected')
        if self.__disconnect_cb is not None:
            self.__disconnect_cb()
