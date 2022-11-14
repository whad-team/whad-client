from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep

def show(packet):
    packet.show()

central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

#print('Using device: %s' % central.device.device_id)
device = central.connect('A4:C1:38:22:01:64', random=False)
print("here")
input()
# Discover
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid)

# Read Device Name characteristic (Generic Access Service)
c = device.get_characteristic(UUID('1800'), UUID('2A00'))
print(c.value)

# Disconnect
device.disconnect()
central.stop()
central.close()
