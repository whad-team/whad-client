from whad.ble import Scanner
from whad.device.uart import UartDevice
from time import time
from threading import Thread

class MyAsyncScanner(Scanner):
    def __init__(self, device):
        super().__init__(device)

    def on_adv_pdu(self, packet):
        packet.show()
        
class AsyncScan(Thread):
    def __init__(self, device):
        super().__init__()
        self.scan = MyAsyncScanner(device)

    def run(self):
        self.scan.start()
        while True:
            self.scan.process()

scanner = AsyncScan(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
scanner.join()

