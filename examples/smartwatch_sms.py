from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep

def on_charac_updated(characteristic, value, indication=False):
    if indication:
        print('[indication] characteristic updated with value: %s' % value)
    else:
        print('[notification] characteristic updated with value: %s' % value)

sender = "Romain"
content = "ABCDABCDABCD"
central = Central(WhadDevice.create('hci0'))
print('Using device: %s' % central.device.device_id)
device = central.connect('EC:F3:23:69:95:CD', random=True)

# Discover
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid + "({})".format(hex(charac.value_handle)))

charac1 = device.get_characteristic(UUID('6006'), UUID('8002'))
charac1.subscribe(
    notification=True,
    callback=on_charac_updated
)

charac2 = device.get_characteristic(UUID('7006'), UUID('8004'))
charac2.subscribe(
    notification=True,
    callback=on_charac_updated
)

input()
charac3 = device.get_characteristic(UUID('6006'), UUID('8001'))
charac3.value = b"\x6f\x71\x71" + bytes([len(sender)+1]) + b"\x00\x00" + bytes(sender,"ascii") + b"\x8f"
charac1.value = b"\x03"
sleep(1)
charac3.value = b"\x6f\x71\x71" + bytes([len(content)+1]) + b"\x00\x01" + bytes(content,"ascii") + b"\x8f"
charac1.value = b"\x03"
acked = False
sleep(1)
charac3.value = bytes.fromhex("6f71711000023230323030353234543030343831")
charac3.value = bytes.fromhex("398f")
charac1.value = b"\x03"
sleep(1)
charac3.value = bytes.fromhex("6f7271020001108f")
charac1.value = b"\x03"

# Disconnect
device.disconnect()
central.stop()
central.close()
