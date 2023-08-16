from whad.phy import Phy, Endianness, OOKModulationScheme, PhysicalLayer, TXPower
from whad.device import WhadDevice
from whad.device.tcp import TCPSocketConnector
from whad.exceptions import WhadDeviceNotFound
from whad.phy.utils.helpers import get_physical_layers_by_domain
from time import time,sleep
import sys
import socket
import logging
logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    try:
        dev = WhadDevice.create("uart")
        dev.open()
        socket = TCPSocketConnector(dev, "localhost", 12345)
        socket.serve()

    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
