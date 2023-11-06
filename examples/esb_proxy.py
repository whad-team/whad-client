from whad.unifying import Dongle, Mouse
from whad.ble.profile import UUID
from whad.device import WhadDevice
from whad.ble.tools.proxy import GattProxy,LinkLayerProxy
from time import sleep
dongle = Dongle(WhadDevice.create('uart0'))
mouse = Mouse(WhadDevice.create('rfstorm0'))


def show_dongle(pkt):
    print("dongle ch#", dongle.channel)
    print("dongle", repr(pkt))

success = False

def show_mouse(pkt):
    global success
    success = True
    print("mouse ch#", mouse.channel)
    print("mouse", repr(pkt))

dongle.attach_callback(show_dongle)
mouse.attach_callback(show_mouse)

dongle.address = "ca:e9:06:ec:a4"
#dongle.start()

mouse.address = "ca:e9:06:ec:a4"
mouse.start()
while True:
    if mouse.synchronize():
        print("channel", mouse.channel)
        dongle.start()
        dongle.channel = mouse.channel

        print("here")



        while True:


            mouse.channel = dongle.channel
            mouse.stack.app.set_keepalive(0)
            mouse.stack.app.keepalive(0)

            mouse.channel = 8
            for _ in range(100):
                mouse.move(-100,0)
#proxy = LinkLayerProxy(peripheral, central, bd_address="a4:c1:38:22:01:64")
#proxy.start()
