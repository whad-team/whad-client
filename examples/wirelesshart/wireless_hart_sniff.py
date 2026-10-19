import sys
import threading
import logging
from time import sleep

from scapy.config import conf
from scapy.all import BrightTheme

from whad.wihart.connector.injector import Injector
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.wihart.exceptions import MissingCryptographicMaterial
from whad.wihart.connector.sniffer import Sniffer
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

conf.color_theme = BrightTheme()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


if __name__ == '__main__':
    sniffer = None
    dev = None

    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <interface> <channel> ")
        sys.exit(1)

    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    try:
        dev = WhadDevice.create(interface)
        sniffer = Sniffer(dev)
        
        sniffer.channel = channel
        sniffer.add_join_key(b"ABCDABCDABCDABCD")
        sniffer.decrypt = True

        sniffer.start()
        sniffer.enable_tsch()

        for pkt in sniffer.sniff():
            if WirelessHart_DataLink_Advertisement not in pkt:
                print(pkt.metadata, repr(pkt))
            
    except WhadDeviceNotFound:
        print(f"[e] Device '{interface}' not found.")
    except (KeyboardInterrupt, SystemExit):
        print("\n[-] Program stopped.")
    finally:
        try:
            if sniffer is not None:
                sniffer.stop()
            if dev is not None:
                dev.close()
        except:
            pass