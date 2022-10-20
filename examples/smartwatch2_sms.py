from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from whad.ble.utils.phy import dewhitening, swap_bits, frequency_to_channel

targeted_channel = frequency_to_channel(2418)
print("Targeting channel {}".format(targeted_channel))

def split_content(content, size):
    c = 0
    data = b""
    for i in content:
        data += bytes([i])
        if len(data) == size:
            yield data
            data = b""
    if len(data) > 0:
        yield data

def on_charac_updated(characteristic, value, indication=False):
    if indication:
        print('[indication] characteristic updated with value: %s' % value)
    else:
        print('[notification] characteristic updated with value: %s' % value)

central = Central(WhadDevice.create('hci0'))
print('Using device: %s' % central.device.device_id)
device = central.connect('C5:61:42:E9:F6:F4', random=True)

# Discover
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid + "({})".format(hex(charac.value_handle)))

rx = device.get_characteristic(UUID('f0080001-0451-4000-b000-000000000000'), UUID('f0080002-0451-4000-b000-000000000000'))
tx = device.get_characteristic(UUID('f0080001-0451-4000-b000-000000000000'), UUID('f0080003-0451-4000-b000-000000000000'))

rx.subscribe(
    notification=True,
    callback=on_charac_updated
)


tx.value = bytes.fromhex("a100000007e60a1317291f0101")

while True:
    sender = "Romain"
    content =  bytes([swap_bits(i) for i in b"ABCDABCDABCDAA" * 10])

    tx.value = bytes.fromhex("c1010101")
    sleep(0.2)
    sequence_number = 1
    tx.value = b"\xc2\x01"+ bytes([len(sender)]) + b"\x14" + bytes([sequence_number]) + b"\x01" + bytes(sender, "ascii") + (b"\x00" * (14 - len(sender)))
    for data in split_content(content, 14):
        sequence_number += 1
        print(dewhitening(15*b"\x00" +data, targeted_channel)[15:])
        tx.value = b"\xc2\x01"+ bytes([len(data)]) + b"\x14" +  bytes([sequence_number]) + b"\x02" +dewhitening(15*b"\x00" +data, targeted_channel)[15:] + (b"\x00" * (14 - len(data)))
    print("Done")
    sleep(0.5)

# Disconnect
device.disconnect()
central.stop()
central.close()
