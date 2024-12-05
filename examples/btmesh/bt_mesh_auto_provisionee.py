from whad.scapy.layers.btmesh import *
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connectors.provisionee import Provisionee
from threading import Thread

from whad.scapy.layers.btmesh import *


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    provisionee = Provisionee(dev, auto_provision=True)
    provisionee.configure(advertisements=True, connection=False)
    provisionee.start()

    onoff = 0
    transaction_id = 1
    while True:
        i = input("Press a key to send a Generic On/Off to the broadcast address ...")
        provisionee.handle_key_press(onoff, transaction_id)
        onoff = int(not onoff)
        transaction_id += 1

except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
