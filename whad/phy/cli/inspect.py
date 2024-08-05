"""PHY inspection tool

This utility provides specific tools for PHY inspection including:

- frequency scanning and RSSI correlation to determine on which channel a device transmits ;
- pattern searching including default bitstream transformation (BLE dewhitening, byte/bit swapping, endianness) ;
- similarity analysis that displays similar chunks of data with a specific color ;
- encryption guessing tools, based on packets analysis.

This tool is meant to be completely PHY agnostic and will work with any hardware that returns packets.

Guessed configuration can be saved for later use, in a dedicated configuration file.
"""
from time import sleep
from binascii import hexlify
from queue import Queue, Empty
from whad.cli.app import CommandLineApp, ApplicationError
from whad.phy.connector import Phy
from whad.ble.exceptions import PeripheralNotFound

import logging
logger = logging.getLogger(__name__)

#logging.basicConfig(level=logging.DEBUG)

class PhyCorrelator(Phy):

    def __init__(self, device, rssi=-100):
        super().__init__(device)
        self.__rssi = rssi
        self.__packet_queue = Queue()
        self.__callback = None

    def set_callback(self, callback):
        """Register a callback to be notified each time a packet
        is received.
        """
        self.__callback = callback

    def on_packet(self, packet):
        """On packet reception, call a callback if set or save the packet
        into our RX queue and wait for the queue to be read later.
        """
        if packet.metadata.rssi > self.__rssi:
            print(hexlify(bytes(packet)))
            if self.__callback is not None:
                self.__callback(packet)
            else:
                self.__packet_queue.put(packet)

    def wait_packet(self, timeout=None):
        """Wait for a packet
        """
        try:
            packet = self.__pkt_queue.get(block=True, timeout=timeout)
            return packet
        except Empty as empty:
            return None

class FrequencyScanner(object):
    """Frequency scanner.

    This analysis module will loop on a range of frequencies and will only
    display packets with RSSI stronger than a given threshold. It can be used
    to easily guess the frequency used by a device to send packets by putting
    this device close to our receiver and make it send as much packets as
    possible.
    """

    def __init__(self, app : CommandLineApp, phy : PhyCorrelator, freq_start : int, freq_end : int,
                 freq_step : int, delay : int):
        """Initialize the frequency scanner.

        :param app: Command-line application this scanner is attached to
        :type app: CommandLineApp
        :param phy: PHY correlator to use
        :type phy: PhyCorrelator
        :param freq_start: Start frequency used for the frequency sweep, in Hz
        :type freq_start: int
        :param freq_end: End frequency used for the frequency sweep, in Hz
        :type freq_end: int
        :param freq_step: Frequency step value in Hz
        :type freq_step: int
        :param delay: Specifies the number of seconds to wait on each frequency
        :type delay: int
        """
        self.__app = app
        self.__phy = phy
        self.__delay = delay
        self.__frequencies = range(freq_start, freq_end, freq_step)
        self.__phy.set_callback(self.on_packet)
        self.__stats = {}
        self.__current_freq = 0
        for f in self.__frequencies:
            self.__stats[f] = 0

    def scan(self):
        """Loop on frequencies, wait `self.__delay` seconds on each and capture packets with RSSI
        bigger than a threshold.
        """
        print('Prepare your device and bring it close to the receiver hardware. Once ready, hit a key')
        print('and make it send as many RF data as possible.')
        print('Hit CTL-C to exit the scanner.')
        try:
            while True:
                for freq in self.__frequencies:
                    self.__phy.set_frequency(freq)
                    self.__current_freq = freq
                    sleep(self.__delay)
        except KeyboardInterrupt as kbd_err:
            # frequency sweep done, display statistics
            print('Frequency scan stopped by user, here are some statistics:')
            self.display_stats()

    def on_packet(self, packet):
        """We received a packet with a valid RSSI

        :param packet: Packet received
        :type packet: Packet
        """
        # Count this packet in our stats
        self.__stats[self.__current_freq] += 1

        # Display the packet
        pass

    def display_stats(self):
        """Show statistics in terminal
        """
        pass


class PhyInspector(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='PHY inspection and analysis tool',
            interface=True,
            commands=False
        )
        self.add_argument(
            '--ble',
            action='store_true',
            dest='ble',
            default=False,
            help='Use BLE PHY (1Mbps, 250kHz deviation)'
        )

        self.add_argument(
            '-f',
            '--freq',
            type=int,
            dest='freq',
            help='Frequency (in Hz)'
        )

        self.add_argument(
            '-r',
            '--rssi',
            dest='rssi',
            type=int,
            default=-100,
            help='RSSI threshold. Only keep packets with RSSI above this value.'
        )

        ######################
        # Analysis modes
        ######################

        self.add_argument(
            '-sf',
            '--search-freq',
            dest='search_freq',
            metavar='FREQ_START:FREQ_END:STEP',
            help='''Search for frequency used to send a packet knowing the modulation scheme.
                    This mode sweeps a range of frequencies and listens for packet and will report
                    those with a strong RSSI specified with the --rssi command-line option.'''
        )

        self.add_argument(
            '-m',
            '--match',
            dest='pattern_match',
            help='''Search hex pattern in received packets, no matter what endianness or whitening used.
            Matching packets are displayed as well as guessed configuration. Patterns may contain wildcards
            noted as ??.
            '''
        )

        self.add_argument(
            '-s',
            '--similar',
            action='store_true',
            default=False,
            help='''Receive raw packets and find the longest common sequence of bytes.
            '''
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
               # Process options (main)
               if self.args.ble:
                   # Configure hardware for BLE 1Mbps
                   self.analyze(ble_1mbps=True, rssi=self.args.rssi, freq=self.args.freq)
            else:
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt as keybd:
            self.warning('phy-inspect stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def analyze(self, freq=None, rssi=-100, ble_1mbps=False):
        phy = PhyCorrelator(self.interface, rssi=rssi)
        if ble_1mbps:
            print('rssi min: %d' % rssi)
            print('freq: %d' % freq)
            # Configure packet correlator
            phy.set_frequency(freq)
            phy.set_gfsk(deviation=250000)
            phy.set_packet_size(50)
            phy.set_sync_word(b'\xAA\xAA')
            phy.sniff_phy()

            # Start sniffing
            phy.start()

            input()
        else:
            self.warning('BLE 1Mbps is the only supported mode')



def phy_inspect_main():
    try:
        app = PhyInspector()
        app.run()
    except ApplicationError as err:
        err.show()
