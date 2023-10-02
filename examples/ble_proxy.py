from whad.ble import Peripheral, Scanner
from whad.device import WhadDevice
from whad.ble.tools.proxy import LinkLayerProxy, GattProxy

import logging
logging.basicConfig(level=logging.DEBUG)

def show(packet):
    print(packet.metadata, repr(packet))


if __name__ == '__main__':
    periph = WhadDevice.create('hci0')
    central = WhadDevice.create('hci1')

    scanner = Scanner(central)
    scanner.start()
    for device in scanner.discover_devices():
        if device.address.lower() == "74:da:ea:91:47:e3":
            adv_data, scan_rsp = device.adv_records.to_bytes(), device.scan_rsp_records.to_bytes()
            break
    scanner.stop()
    print("SCAN_DATA", scan_rsp.hex())
    proxy = LinkLayerProxy(periph, central, bd_address="74:da:ea:91:47:e3", adv_data=adv_data, scan_data=scan_rsp,  spoof=True)#, , , spoof=True)
    try:
        #proxy = GattProxy(periph, central, bd_address="74:da:ea:91:47:e3")
        proxy.start()
        input()
        proxy.close()
    except KeyboardInterrupt:
        proxy.close()
