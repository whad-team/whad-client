from whad.device import WhadDevice, WhadDeviceConnector
from whad.zigbee.connector.enddevice import EndDevice

from prompt_toolkit import print_formatted_text, HTML

from whad.cli.shell import InteractiveShell, category
from whad.dot15d4.exceptions import InvalidDot15d4AddressException
from whad.dot15d4.address import Dot15d4Address

from .cache import ZigbeeNetworksCache
from .helpers import create_enddevice

INTRO='''
zigbee-enddevice, the WHAD Zigbee end device utility
'''

class ZigbeeEndDeviceShell(InteractiveShell):
    """Zigbee End Device interactive shell
    """

    def __init__(self, interface: WhadDevice = None, connector=None, network_panid=None):
        super().__init__(HTML('<b>zigbee-enddevice></b> '))

        # If interface is None, pick the first matching our needs
        self.__interface = interface
        self.__cache = ZigbeeNetworksCache()
        self.__wireshark = None

        # If connector is not provided
        if connector is None:
            # Reset target info and connector.
            self.__target_network = None
            self.__target_network_panid = None
            self.__connector: WhadDeviceConnector = EndDevice(self.__interface)
        else:
            # If connector provided, consider the network already connected
            self.__connector = connector
            self.__target_network = None
            self.__target_network_panid = network_panid

        self.intro = INTRO

        self.update_prompt()


    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        """
        if not self.__target_network_panid:
            self.set_prompt(HTML('<b>zigbee-enddevice></b> '), force)
        else:
            self.set_prompt(HTML('<b>zigbee-enddevice|<ansicyan>%s</ansicyan>></b> ' % self.__target_network_panid), force)


    @category('Networks discovery')
    def do_scan(self, args):
        """scan surrounding networks and show a small summary

        <ansicyan><b>scan</b></ansicyan>

        Scan surrounding networks and report them in this console in real-time.

        The following information is provided:
         - <b>Channel:</b> represents the channel where the network is deployed
         - <b>Pan ID:</b> short identifier of the ZigBee network
         - <b>Ext. Pan ID:</b> long (extended) identifier of the ZigBee network
         - <b>Joining:</b> indicates if joining the network is allowed or not

        You can stop a scan by hitting <b>CTL-c</b> at any time, the discovered networks are kept in
        memory and would be available in autocompletion.
        """

        # Start scanning
        print_formatted_text(HTML('<ansigreen>Channel   PAN ID   Ext. PAN ID             Joining</ansigreen>'))
        self.__connector.start()
        try:
            for network in self.__connector.discover_networks():
                # Show network
                print(
                        network.channel," "*6,
                        hex(network.pan_id)," ",
                        network.extended_pan_id,
                        "permitted" if network.is_joining_permitted() else "forbidden"
                )

                # Add network to cache
                self.__cache.add(network)
        except KeyboardInterrupt as keybd_int:
            print('\rScan terminated by user')

        if self.__wireshark is not None:
            self.__wireshark.detach()

        self.__connector.stop()


    @category('Networks discovery')
    def do_networks(self, arg):
        """list discovered networks

        <ansicyan><b>networks</b></ansicyan>

        List every discovered networks so far, through the <ansicyan>scan</ansicyan> command.
        This command displays the content of the console networks cache.
        """
        print_formatted_text(HTML('<ansigreen>Channel   PAN ID   Ext. PAN ID             Joining</ansigreen>'))
        for network in self.__cache.iterate():
            # Show network
            print(
                    network['info'].channel," "*6,
                    hex(network['info'].pan_id)," ",
                    network['info'].extended_pan_id,
                    "permitted" if network['info'].is_joining_permitted() else "forbidden"
            )



    @category('Network interaction')
    def do_join(self, args):
        """join a network

        <ansicyan><b>join</b> <i>[ Extended PAN ID or PAN ID ]</i> </ansicyan>

        Initiate a ZigBee join to a specific network by its extended PAN ID or
        PAN ID. If multiple networks have the same PAN ID, the first one will be
        picked for join.
        """

        if len(args) < 1:
            self.error('<u>join</u> requires at least one parameter (extended PAN ID or PAN ID).\ntype \'help join\' for more details.')
            return

        try:

            try:
                target = self.__cache[args[0]]
                target_pan_id = target['info'].extended_pan_id

            except IndexError as notfound:
                # If target not in cache, we are expecting an extended PAN ID or a PAN ID
                try:
                    target_pan_id = Dot15d4Address(args[0])
                except InvalidDot15d4AddressException:
                    self.error('You must provide a valid extended PAN ID or PAN ID.')
                    return
        except:
            return
