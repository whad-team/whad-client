import sys
import threading
import logging
from time import sleep

from scapy.config import conf
from scapy.all import BrightTheme

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.wihart.exceptions import MissingCryptographicMaterial
from whad.wihart.connector.sniffer import Sniffer
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

conf.color_theme = BrightTheme()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def cli_interaction_worker(sniffer_instance):
    while not getattr(sniffer_instance, '_synchronized', False):
        sleep(0.5)
    
    print("\n\033[92m[+] Connection and TSCH synchronization established. Interactive mode ready.\033[0m")
    
    while True:
        try:
            print("\n" + "="*40)
            print(f"[-] Current Stack ASN: {sniffer_instance.network.asn if sniffer_instance.network else 'Unknown'}")
            print(f"[-] Active spoofed nodes: {list(sniffer_instance.spoofed_nodes)}")
            print("="*40)
            
            cmd = input("Actions: [ping] [deauth] [disconnect] [spoof] [exit]\nChoice > ").strip().lower()
            if cmd == "network":
                print(sniffer.network)
            if cmd == "keys":
                print(sniffer.decryptor)
            if cmd == "ping":
                dst = int(input("Target node (ID) > "))
                graph = int(input("Graph ID > "))
                print("[*] Injecting ping_request...")
                sniffer_instance.ping_request(dst, graph=graph)
            elif cmd == "exit":
                print("[*] Exiting...")
                break

        except ValueError:
            print("\033[91m[!] Error: Invalid numerical input.\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Injection error: {e}\033[0m")

if __name__ == '__main__':
    sniffer = None
    dev = None

    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <interface> <channel>")
        sys.exit(1)

    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    try:
        dev = WhadDevice.create(interface)
        sniffer = Sniffer(dev)
        
        sniffer.channel = channel
        sniffer.add_join_key(b"ABCDABCDABCDABCD")
        sniffer.decrypt = True
        sniffer.spoofed_nodes = set()

        sniffer.start()

        cli_thread = threading.Thread(target=cli_interaction_worker, args=(sniffer,), daemon=True)
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