import sys
from time import sleep
import logging
import os

from whad.cli.app import CommandLineDeviceSource, run_app
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement
from whad.wihart.connector.sniffer import Sniffer
from scapy.config import conf
from scapy.all import BrightTheme
from whad.device.unix import UnixConnector,UnixSocketServer
from whad.device import Bridge


conf.color_theme = BrightTheme()
logger = logging.getLogger(__name__)
STATE_FILE = "/tmp/network_state.json"
TMP_FILE = "/tmp/network_state_tmp.json"

class WiHARTsynchApp(CommandLineDeviceSource):
    """Wireless HART synchronization app
    """

    def __init__(self):
        super().__init__(
            description="This tool permits the synchronization to a wirelessHART network " \
            "in order to sniff or inject traffic",
            interface=True,
            commands=False
        )

        self.add_argument(
            '-c', '--channel',
            metavar='CHANNEL',
            dest='channel',
            type=int,
            default=None,
            help="Channel to listen on for synchronization, if not specified the tool will look for a channel on its own",
        )

        self.add_argument(
            '-d', '--decrypt',
            dest='decrypt',
            action='store_true',
            default=False,
            help="Decrypt communications and only handle the device when keys are picked up",
        )

        self.add_argument(
                    '-s', '--show-packets',
                    dest='show',
                    action='store_true',
                    default=False,
                    help="Show packets received while synchronization",
                )

        self.add_argument(
                            '-ha', '--hide-advertisement',
                            dest='hide_adv',
                            action='store_true',
                            default=False,
                            help="Hide advertisements",
                        )

        self.add_argument(
            '-j', '--join-key',
            metavar='JOIN_KEY',
            dest='join_key',
            type=bytes.fromhex,         
            default=None,
            help="Join key (hex) used to decrypt/join the network",
        )

        self.add_argument(
            '-m', '--mote',
            dest='mote',
            type=int,
            default=None,
            help="Mote joining the network to check that its keys were obtained"
        )


    def _open_pipe(self, path):
        unix_server = UnixConnector(UnixSocketServer(parameters={
            'domain': 'wihart',
            'mote_targeted': str(self.args.mote),
            'network_state': path,
        }))
 
        while not unix_server.device.opened:
            if unix_server.device.timedout:
                logger.error("[whart-sync] no client connected (timeout)")
                return None
            sleep(0.5)
 
        logger.info("[whart-sync] client connected")
        return unix_server




    def run(self):
        
        get_keys = False # only handle after keys are captured
        try:
            self.pre_run()

            # Check tool is piped and interface is provided 
            if not self.is_stdout_piped():
                self.error("This tool is destined for synchronization before handling over to another  ")
                return
            if self.interface is None : 
                self.error("You need to specify an interface with option --interface.")
                return

            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)

            if os.path.exists(TMP_FILE):
                os.remove(TMP_FILE)

            unix_server = self._open_pipe(STATE_FILE)
            if unix_server is None:
                return

            # Create our sniffer
            sniffer = Sniffer(self.interface)
            sniffer.start()
            sniffer.enable_tsch() 
            if self.args.channel is not None : 
                sniffer.channel = self.args.channel
            else : 
                
                print("Detect channel for synch", file=sys.stderr)
                sniffer.detect_channel(show=False)
                print("Synchronization is done..", file=sys.stderr)

            
            if self.args.decrypt :
                get_keys = True
                sniffer.decrypt = True
            if self.args.join_key is not None:
                sniffer.add_join_key(self.args.join_key)
            
            for pkt in sniffer.sniff():
                if self.args.show:
                    if self.args.hide_adv :
                        if not WirelessHart_DataLink_Advertisement in pkt:
                            print(pkt.metadata, repr(pkt), file=sys.stderr)
                    else:
                        print(pkt.metadata, repr(pkt), file=sys.stderr)
                if sniffer.is_synchronized():
                    if get_keys :
                        decryptor = sniffer.decryptor
                        if (decryptor.get_network_key() is not None # check if network keys are captured
                            and decryptor.get_broadcast_session_key(0xf980, 0xffff) is not None # check if broadcast keys are captured to handle 
                            and decryptor.get_broadcast_session_key(0xf981, 0xffff) is not None) :
                                # If we are looking for a specified mote
                                if (self.args.mote is not None 
                                    and decryptor.get_unicast_session_key(0xf980, self.args.mote) is not None
                                    and decryptor.get_unicast_session_key(0xf981, self.args.mote) is not None):
                                        break
                                else:
                                    break # we can assume all keys are captured and handlek
                        else:
                            continue
                    else:
                        break
            
            sniffer.save_network_state(TMP_FILE)
            
            self.warning("Synchronized, handing over the interface...")
            
            os.replace(TMP_FILE, STATE_FILE) # atomic replacement

            bridge = Bridge(sniffer, unix_server)

            bridge.join()

            

                    
                    
        except KeyboardInterrupt:
            self.warning('whart-sync stopped (CTRL-C)')
            return
        self.post_run()


        

def whart_sync_main():
    """WirelessHART tool synchronization main routine.
    """
    app = WiHARTsynchApp()
    run_app(app)