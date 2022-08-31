from whad.ble import Central
from whad.ble.profile import UUID
from whad.device import WhadDevice


central = Central(WhadDevice.create('hci1'))
print('Using device: %s' % central.device.device_id)
device = central.connect('ff:ff:ff:f0:08:a3')

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
