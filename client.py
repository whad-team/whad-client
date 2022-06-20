from whad.ble import Scanner, Central
from whad.device.uart import UartDevice
from time import time,sleep
from threading import Thread

scanner = Scanner(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
while True:
    try:
        for rssi, device in scanner.discover_devices():
            print('%d - %s' % (rssi, device.AdvA))
    except KeyboardInterrupt as exc:
        scanner.stop()
        scanner.device.close()
        break
"""
class MyAsyncScanner(Scanner):
    def __init__(self, device):
        super().__init__(device)

    def on_adv_pdu(self, rssi, packet):
        print('%d - %s' %(
            rssi,
            packet.AdvA
        ))
        
class AsyncScan(Thread):
    def __init__(self, device):
        super().__init__()
        self.scan = MyAsyncScanner(device)

    def run(self):
        self.scan.start()
        while True:
            self.scan.process()
"""

""" Asynchronous scanner
scanner = AsyncScan(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
scanner.join()
"""

""" Synchronous scanner 
scanner = Scanner(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
while True:
    try:
        for rssi, device in scanner.discover_devices():
            if (rssi >= -65):
                print('%d - %s' % (rssi, device.AdvA))
    except KeyboardInterrupt as exc:
        scanner.stop()
        break


class deleg(Thread):
    def __init__(self, central):
        super().__init__()
        self.central = central
    
    def run(self):
        sleep(6)
        self.central.send_ctrl_pdu([0x12])

central = Central(UartDevice('/dev/ttyUSB0', 115200))
central.connect_to('D4:3B:04:2C:AD:16')
#central.connect_to('11:75:58:69:52:A4')
timeout = deleg(central)
print(central.start())
timeout.start()
try:
    while True:
        messages = central.process()
        if len(messages) > 0:
            for message in messages:
                print(message)
                
except KeyboardInterrupt as exc:
    central.stop()
"""

