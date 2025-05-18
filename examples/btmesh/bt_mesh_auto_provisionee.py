from whad.scapy.layers.btmesh import *
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connectors.provisionee import Provisionee
from threading import Thread

from whad.btmesh.stack.utils import MeshMessageContext

from whad.scapy.layers.btmesh import *


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    provisionee = Provisionee(dev)
    profile = provisionee.profile
    profile.auto_provision()
    provisionee.start()

    onoff = 0
    transaction_id = 1

    while True:
        # create context in loop! (otherwise values get overwritten when sending ...)
        ctx = MeshMessageContext()
        ctx.src_addr = profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xff"
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
