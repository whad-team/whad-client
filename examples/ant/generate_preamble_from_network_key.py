from whad.ant.crypto import generate_sync_from_network_key
import sys

if len(sys.argv) != 2:
    print("Usage: ./"+sys.argv[0]+" <key>")
    exit(1)

sync = generate_sync_from_network_key(bytes.fromhex(sys.argv[1]))
print("-> {:04x}".format(sync))