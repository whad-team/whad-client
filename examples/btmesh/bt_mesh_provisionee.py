from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisionee import Provisionee
from time import sleep
from whad.btmesh.stack.utils import (
    MeshMessageContext,
    get_address_type,
    UNICAST_ADDR_TYPE,
)
from whad.scapy.layers.btmesh import BTMesh_Model_Generic_OnOff_Set


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    provisionee = Provisionee(dev)

    print("Sending Unprovisioned Device Beacons, waiting for provisioning ....\n\n")
    provisionee.start_provisioning()

    if provisionee.profile.is_provisioned:
        print("Node is provisioned !")
    else:
        print("Node has not been provisioned")
        dev.close()
        exit(1)


    # retrieve generic onoff client of the local node of primary element
    model = provisionee.profile.local_node.get_element(0).get_model_by_id(0x1001)
    if model is None:
        print(
            "this profile does not implement the generic onoff client in primary element, fail."
        )
        dev.close()
        exit(1)

    # Create context of message to send
    ctx = MeshMessageContext()
    ctx.src_addr = provisionee.profile.get_primary_element_addr()
    ctx.dest_addr = 0xFFFF
    ctx.application_key_index = 0
    ctx.net_key_id = 0
    ctx.ttl = 127

    onoff = 0

    while True:
        # the packet to send (we switch between 0 and 1)
        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=onoff)

        addr = input(
            "\nPress a key to send a Generic On/Off to the broadcast address with app-key 0 and net-key 0 (make sure to have them ...)\n"
            "Enter an address of destination to send to a specific destination and wait for ackowlegement :  "
        )
        try:
            ctx.dest_addr = int(addr, 0) & 0xFFFF
        except ValueError:
            ctx.dest_addr = 0xFFFF

        # Only wait for ack with status if destination is a unicast adress
        is_acked = get_address_type(ctx.dest_addr) == UNICAST_ADDR_TYPE

        print("\nSending message to 0x%x...\n" % ctx.dest_addr)
        response = provisionee.send_model_message(
            model=model, message=(pkt, ctx), is_acked=is_acked
        )

        if is_acked:
            if response is None:
                print("Did not receive any response from 0x%x\n\n" % ctx.dest_addr)
            else:
                print("Received status packet from 0x%x\n\n" % ctx.dest_addr)
                resp_pkt, resp_ctx = response
                resp_pkt.show()

        onoff = int(not onoff)


except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
