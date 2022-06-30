"""Bluetooth Low Energy device abstraction


class Device(BleDevice):

    class battery(BleService):
        uuid = UUID(0x2A00)
        carac = Characteristic('2A00', b'', READ)
        carac2 = Characteristic('2B00', b'Toto', READ)

        def on_notify()

    class MonAutreService(BleService):

        carac = ...
"""
from whad.domain.ble.characteristic import Characteristic

class ServiceModel:
    """BLE Service model mapping
    """

    def __init__(self, device):
        self.__device = device
        self.__characteristics = []

    def prepare_model(self, start_handle):
        properties = dir(self)
        for prop in properties:
            if not prop.startswith('_'):
                prop_obj = getattr(self, prop)
                if not callable(prop_obj) and isinstance(prop_obj, Characteristic):
                    
                    # Found a characteristic, set handle
                    prop_obj.handle=start_handle
                    start_handle += 2
                    setattr(self, prop, prop_obj)
                    
                    # Register characteristic
                    self.__characteristics.append(prop_obj)

        return start_handle

    @property
    def device(self):
        return self.__device

    def show(self):
        """Display service characteristics
        """
        for characteristic in self.__characteristics:
            print('  - Characteristic %s (handle: %d)' % (
                characteristic.uuid,
                characteristic.handle
            ))
            print('    -> Value handle: %d' % characteristic.value_handle)

class DeviceModel:
    """Device Services and Characteristics model mapping
    """

    def __is_service_class(self, x):
        return ServiceModel in x.__bases__

    def __init__(self, start_handle=1):
        """Introspect this class and build the device model
        """
        self.__services = []
        properties = dir(self)
        print(properties)
        for prop in properties:
            if not prop.startswith('_'):
                prop_obj = getattr(self, prop)
                print(prop, type(prop_obj))
                if callable(prop_obj) and hasattr(prop_obj, '__bases__') and ServiceModel in prop_obj.__bases__:
                    print(prop)
                    # Found a ServiceModel class, instanciate based on its name
                    service = prop_obj(self)
                    service.handle = start_handle
                    start_handle = service.prepare_model(start_handle + 1)
                    
                    # Register as a new attribute
                    setattr(self, prop, service)

                    # Register in our known services
                    self.__services.append(service)

    def show(self):
        """Display device attributes
        """
        for service in self.__services:
            print('[+] Service %s (handle: %d)' % (service.uuid, service.handle))
            service.show()



                    





    