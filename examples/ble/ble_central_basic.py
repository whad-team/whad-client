from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice
import sys

if len(sys.argv) >= 2:
    interface = sys.argv[1]
    # Create the Central connector & the WHAD device
    central = Central(WhadDevice.create(interface))

    # Connect to a specific device
    device = central.connect('74:da:ea:91:47:e3', random=False)

    # Discover and display the profile
    device.discover()
    print("[i] Discovered profile")
    for service in device.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)

    # Get the device name
    device_name = device.get_characteristic(UUID(0x1800), UUID(0x2A00))
    print("[i] Device name: ", device_name.value)

    # Disconnect
    device.disconnect()
    central.close()
else:
    print("Usage: ", sys.argv[0]+" <interface>")
