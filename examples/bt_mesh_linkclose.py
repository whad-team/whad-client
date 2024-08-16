from whad.bt_mesh.connectors.linkcloser import PBAdvLinkCloser
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ble.exceptions import ConnectionLostException

from time import sleep
import sys

if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [device]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]


try:
    dev = WhadDevice.create(interface)
    linkcloser = PBAdvLinkCloser(dev)
    linkcloser.configure(advertisements=True, connection=False)
    linkcloser.start()
    print("LINK CLOSER STARTED")

    while True:
        linkcloser.polling_rx_packets()
        sleep(0.05)
except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
