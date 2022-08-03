from whad.domain.ble import Peripheral
from whad.domain.ble.attribute import UUID
from whad.domain.ble.profile import PrimaryService, Characteristic, GenericProfile
from whad.device.uart import UartDevice
from time import sleep

class MyPeripheral(GenericProfile):

    device = PrimaryService(
        uuid=UUID(0x1800),

        device_name = Characteristic(
            uuid=UUID(0x2A00),
            permissions = ['read', 'write'],
            notify=True,
            value=b'TestDevice'
        ),
    )

my_profile = MyPeripheral()
periph = Peripheral(UartDevice('/dev/ttyUSB0', 115200), profile=my_profile)

# Enable peripheral (advertised as 'ABCD')
periph.set_bd_address('11:22:33:44:55:99')
periph.enable_peripheral_mode(adv_data=bytes([0x02, 0x01, 0x06, 0x05, 0x9, 0x41, 0x42, 0x43, 0x44]))

# Sleep 10 seconds and update device name
print('Press a key to update device name')
input()
my_profile.device.device_name.value = b'TestDeviceChanged'
