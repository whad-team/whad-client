from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisionee import Provisionee
from time import sleep
from whad.btmesh.stack.utils import MeshMessageContext


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    provisionee = Provisionee(dev)
    provisionee.start()
    provisionee.start_unprovisioned_beacons_sending()

    print("Sending Unprovisioned Device Beacons, waiting for provisioning ....")

    while not provisionee.profile.is_provisioned:
        sleep(1)

    print("Node is provisioned !")

    onoff = 0
    transaction_id = 1

    while True:
        # create context in loop! (otherwise values get overwritten when sending ...)
        ctx = MeshMessageContext()
        ctx.src_addr = provisionee.profile.get_primary_element_addr()
        ctx.dest_addr = 0xFFFF
        ctx.application_key_index = 0
        ctx.net_key_id = 0
        ctx.ttl = 127

        i = input("Press a key to send a Generic On/Off to the broadcast address ...")
        provisionee.do_onoff(onoff, ctx, transaction_id)
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
