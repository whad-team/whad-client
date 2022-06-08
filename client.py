from whad.device import UartDevice
from whad import WhadDomain

d = UartDevice()
d.open()
d.discover()
if d.has_domain(WhadDomain.BtLE):
    print('BLE is supported')

