import sys
import threading
import logging

from scapy.config import conf
from scapy.all import BrightTheme

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import ANSI

from whad.cli.app import CommandLineApp, run_app
from whad.wihart.connector.sniffer import Sniffer
from whad.wihart.connector.injector import Injector
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

conf.color_theme = BrightTheme()
logger = logging.getLogger(__name__)

last_pkt = None

class WiHARTattackShell(CommandLineApp):
    """Interactive WirelessHART tool.

    Sniffs in the main loop and lets the user inject traffic from an
    interactive prompt. 
    A toolbar shows live status (sync state, ASN, last time offset)"""

    def __init__(self):
        super().__init__(
            description="Interactive WirelessHART sniff/inject tool",
            interface=True,
            commands=False,
        )
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

        handlers = {
            "help": self._cmd_help,
            "sync": self._cmd_sync,
            "join-key": self._cmd_join_key,
            "network": self._cmd_network,
            "keys": self._cmd_keys,
            "show-packets": self._cmd_show_packets,
            "decrypt": self._cmd_decrypt,
            "ping": self._cmd_ping,
            "adv": self._cmd_adv,
            "ka": self._cmd_ka,
            "deauth": self._cmd_deauth,
            "save": self._cmd_save,
        }

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
                handler = handlers.get(name)
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
        print("  sync           synchronize")
        print("  join-key       change stored join_key")
        print("  network        print the network state")
        print("  keys           print the key store")
        print("  show-packets   show/hide received packets")
        print("  decrypt        attempt to decrypt traffic")
        print("  ping           inject a ping request (prompts for params)")
        print("  adv            inject a fake advertisement (prompts for params)")
        print("  ka             inject a keep-alive (prompts for target)")
        print("  deauth         inject a suspend device packet")
        print("  save           save network configuration to a file")
        print("  exit / quit    leave")

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

    # --- Main routine -----------------------------------------------------------
    def run(self):
        global last_pkt
        self.pre_run()
        if self.interface is None:
            self.error("You need to specify an interface with --interface/-i.")
            return
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
            self.post_run()


def whart_attack_main():
    """Interactive WirelessHART tool main routine."""
    app = WiHARTattackShell()
    run_app(app)