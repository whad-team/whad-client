import sys
from whad.ble import Peripheral
from whad.common.monitors import WiresharkMonitor
from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile
from whad.device import WhadDevice

# Define your custom profile
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

if len(sys.argv) >= 2:
    # Create the connector & the profile
    my_profile = MyPeripheral()
    periph = Peripheral(WhadDevice.create(sys.argv[1]), profile=my_profile)

    # Attach a Wireshark monitor to the connector to visualize live traffic in wireshark
    monitor = WiresharkMonitor()
    monitor.attach(periph)
    monitor.start()

    try:
        # Start the peripheral mode
        periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
            AdvCompleteLocalName(b'TestMe!'),
            AdvFlagsField()
        ))

        # Wait for an user input & update device name
        print('Press a key to update device name')
        input()
        my_profile.device.device_name.value = b'TestDeviceChanged'

        # Wait for an user input & stop connector and monitor
        print('Press a key to disconnect')
        input()
        periph.stop()
        monitor.close()
        periph.close()

    except KeyboardInterrupt:
        periph.close()
        monitor.close()

else:
    print("Usage:", sys.argv[0], "<interface>")
