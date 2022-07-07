"""Bluetooth Low Energy device abstraction
"""

from whad.domain.ble.profile import GenericProfile

class PeripheralCharacteristicDescriptor:

    def __init__(self, descriptor, gatt):
        self.__descriptor = descriptor
        self.__gatt = gatt

class PeripheralCharacteristic:
    """Characteristic wrapper for peripheral devices

    Instruments gatt to read/write a remote characteristic.
    """
    def __init__(self, characteristic, gatt):
        self.__characteristic = characteristic
        self.__gatt = gatt

    def uuid(self):
        return self.__characteristic.uuid

    def read(self):
        """Read characteristic value
        """
        return self.__gatt.read(self.__characteristic.value_handle)

    def write(self, value):
        """Set characteristic value
        """
        if isinstance(value, bytes):
            return self.__gatt.write(self.__characteristic.value_handle, value)
        else:
            print('NOPE')

    def descriptors(self):
        for desc in self.__characteristic.descriptors():
            yield PeripheralCharacteristicDescriptor(
                desc,
                self.__gatt
            )


class PeripheralService:
    """Service wrapper for peripheral devices
    """

    def __init__(self, service, gatt):
        self.__service = service
        self.__gatt = gatt

    def uuid(self):
        return self.__service.uuid

    def get_characteristic(self, uuid):
        for charac in self.__service.characteristics():
            if charac.uuid == uuid:
                return PeripheralCharacteristic(
                    charac,
                    self.__gatt
                )
        return None

    def characteristics(self):
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

    def __init__(self, gatt_client):
        super().__init__()
        self.__gatt = gatt_client

    def discover(self):
        """Discovers services, characteristics and descriptors.

        This method must be called before accessing any service or characteristic,
        as it is required to retrieve the corresponding GATT handles.
        """
        # Discover
        self.__gatt.discover()

    def services(self):
        """Enumerate device services.
        """
        for service in self.__gatt.services():
            yield PeripheralService(service, self.__gatt)

    def get_characteristic(self, service_uuid, charac_uuid):
        """Get a PeripheralCharacteristic object representing a characteristic
        defined by the given service UUID and characteristic UUID.

        :return: PeripheralCharacteristic object on success, None if not found.
        """
        service = self.get_service(service_uuid)
        if service is not None:
            return service.get_characteristic(charac_uuid)
        return None

    def get_service(self, uuid):
        """Retrieve a PeripheralService object given its UUID.
        """
        for service in self.__gatt.services():
            if service.uuid == uuid:
                return PeripheralService(service, self.__gatt)
        return None


    


                    





    