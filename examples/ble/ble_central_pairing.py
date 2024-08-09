from whad.ble import Central, BDAddress
from whad.ble.profile import UUID
from whad.ble.stack.smp import Pairing, IOCAP_NOINPUT_NOOUTPUT, CryptographicDatabase
from whad.device import WhadDevice
import sys

def show(packet):
    print(repr(packet))

if len(sys.argv) >= 2:
    interface = sys.argv[1]
    # Create the WHAD device
    dev = WhadDevice.create(interface)

    # Create a security database
    security_database = CryptographicDatabase()

    # Create the Central connector & use the provided security database
    central = Central(dev, security_database = security_database)
    central.attach_callback(show)
    # Connect to a specific device
    device = central.connect('74:da:ea:91:47:e3', random=False)

    # Discover and display the profile
    device.discover()
    print("[i] Discovered profile")
    for service in device.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)


    success = device.pairing(
        pairing = Pairing(
            lesc=False,
            mitm=False,
            bonding=True,
        )
    )
    if success:
        print("Pairing successful !")
        cryptographic_material = central.security_database.get(address=BDAddress("74:da:ea:91:47:e3"))
        print("Long term key:", cryptographic_material.ltk)
        print("Cryptographic Material:", cryptographic_material)

        print("Disconnecting !")
        device.disconnect()

        # Connect again and start encryption
        device = central.connect('74:da:ea:91:47:e3', random=False)
        device.start_encryption()

        device.discover()
        # Get the device name
        device_name = device.get_characteristic(UUID(0x1800), UUID(0x2A00))
        print("[i] Device name: ", device_name.value)

        device.disconnect()
        central.close()

    else:
        print("Pairing failure, exiting...")
        exit(1)

else:
    print("Usage: ", sys.argv[0]+" <interface>")
