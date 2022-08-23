from whad.ble import Peripheral
from whad.common.monitors import PcapWriterMonitor
from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile
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
monitor = PcapWriterMonitor("test.pcap")
monitor.attach(periph)
monitor.start()
periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
    AdvCompleteLocalName(b'TestMe!'),
    AdvFlagsField()
))

# Sleep 10 seconds and update device name
print('Press a key to update device name')
input()
my_profile.device.device_name.value = b'TestDeviceChanged'
