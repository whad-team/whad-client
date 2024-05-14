from whad.phy import Phy, Endianness, OOKModulationScheme, PhysicalLayer, TxPower
from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.device.tcp import UnixSocketDevice
from whad.exceptions import WhadDeviceNotFound
from whad.phy.utils.helpers import get_physical_layers_by_domain
from time import time,sleep
import sys
import socket
import logging
logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    try:
        dev = WhadDevice.create("toto:12345")#UnixSocketDevice(interface=("localhost", 12341))#
        c = Sniffer(dev)
        c.configure(advertisements=True)
        c.start()
        for i in c.sniff():
            print(i)

    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
