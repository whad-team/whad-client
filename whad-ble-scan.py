"""WHAD Bluetooth Low Energy scanner

This script is a simple BLE device scanner that prints detected devices to
stdout.

TODO: Parse AD records and handle display ...
"""
import sys
from argparse import ArgumentParser

from whad.device import WhadDevice
from whad.common.monitors import PcapWriterMonitor
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady

from whad.ble import BLE, Scanner, Sniffer, BDAddress, AdvDataFieldList, \
    AdvCompleteLocalName, AdvDataError, AdvDataFieldListOverflow, \
    AdvShortenedLocalName

from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_ADV_NONCONN_IND, \
    BTLE_ADV_DIRECT_IND, BTLE_SCAN_RSP

class BleDevice(object):
    """Store information about a device
    """

    def __init__(self, rssi, bd_address, adv_data, undirected=True, connectable=True):
        self.__bd_address = bd_address
        self.__adv_data = adv_data
        self.__rssi = rssi
        self.__got_scan_rsp = False
        self.__undirected = undirected
        self.__connectable = connectable

    @property
    def address(self):
        return str(self.__bd_address)

    @property
    def rssi(self):
        return self.__rssi

    @property
    def got_scan_rsp(self):
        return self.__got_scan_rsp

    def __repr__(self):
        """Show device information
        """
        # Do we have a name ?
        complete_name = None
        short_name = None
        for record in self.__adv_data:
            if isinstance(record, AdvShortenedLocalName):
                short_name = record.name.decode('utf-8')
            elif isinstance(record, AdvCompleteLocalName):
                complete_name = record.name.decode('utf-8')

        # Pick the best name
        if complete_name:
            name = 'name:"%s"' % complete_name
        elif short_name:
            name = 'name:"%s"' % short_name
        else:
            name = ''

        # Generate device summary
        return '[%4d dBm] %s %s' % (
            self.__rssi,
            self.__bd_address,
            name
        )


    def update_rssi(self, rssi=0):
        """Update device RSSI
        """
        self.__rssi = rssi

    def set_scan_rsp(self, scan_rsp):
        """Update device advertisement data
        """
        if not self.__got_scan_rsp:
            for record in scan_rsp:
                self.__adv_data.add(record)
            self.__got_scan_rsp = True


class BleDevicesDB(object):
    """Bluetooth Low Energy devices database.

    This class stores information about discovered devices.
    """

    def __init__(self):
        self.__db = {}

    def find_device(self, address):
        if address in self.__db:
            return self.__db[address]
        else:
            return None

    def register_device(self, device):
        """Register or update a device
        """
        self.__db[device.address] = device

    def on_device_found(self, rssi, adv_packet, filter_addr=None):
        """Device advertising packet or scan response received.

        Parse the incoming packet and handle device appropriately.
        """
        if adv_packet.haslayer(BTLE_ADV_IND):
            bd_address = BDAddress(adv_packet[BTLE_ADV_IND].AdvA)
            try:
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = BleDevice(
                    rssi,
                    bd_address,
                    adv_list
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    print(device)
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass

        elif adv_packet.haslayer(BTLE_ADV_NONCONN_IND):
            try:
                bd_address = BDAddress(adv_packet[BTLE_ADV_NONCONN_IND].AdvA)
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_NONCONN_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = BleDevice(
                    rssi,
                    bd_address,
                    adv_list,
                    connectable=False
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    print(device)
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass

        elif adv_packet.haslayer(BTLE_SCAN_RSP):
            try:
                bd_address = BDAddress(adv_packet[BTLE_SCAN_RSP].AdvA)
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_SCAN_RSP].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                if str(bd_address) in self.__db:
                    device = self.__db[str(bd_address)]
                    if not device.got_scan_rsp:
                        device.set_scan_rsp(adv_list)
                        print(device)
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument(
        '-m',
        '--match',
        dest='bd_addr',
        default=None,
        type=str,
        help='Filter by BD address'
    )
    parser.add_argument(
        '-r',
        '--rssi',
        dest='rssi',
        default='100',
        type=int,
        help='minimal RSSI threshold, in -dBm (default: 100, meaning -100 dBm)'
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        default=None,
        type=str,
        help='Output PCAP file'
    )
    parser.add_argument(
        'device',
        metavar='DEVICE',
        type=str,
        help='WHAD device'
    )

    args = parser.parse_args()
    scanner = None
    monitor = None
    try:
        # Create our device DB
        dev_db = BleDevicesDB()

        # Instanciate device
        device = WhadDevice.create(args.device)

        ble_device = BLE(device)
        if ble_device.can_scan():
            # Create a BLE scanner
            scanner = Scanner(device)
            if args.output is not None:
                monitor = PcapWriterMonitor(args.output)
                monitor.attach(scanner)
                monitor.start()
            # Start scanning
            scanner.start()
            for advertisement in scanner.discover_devices():
                if advertisement.metadata.rssi > -args.rssi:
                    dev_db.on_device_found(
                        advertisement.metadata.rssi,
                        advertisement,
                        filter_addr=args.bd_addr
                    )

        elif ble_device.can_sniff_advertisements():
            # Create a sniffer
            scanner = Sniffer(device)
            if args.output is not None:
                monitor = PcapWriterMonitor(args.output)
                monitor.attach(scanner)
                monitor.start()

            scanner.configure(advertisements=True)

            scanner.start()
            for pkt in scanner.sniff():
                if pkt.metadata.rssi > -args.rssi:
                    dev_db.on_device_found(
                        pkt.metadata.rssi,
                        pkt,
                        filter_addr=args.bd_addr
                    )

    except WhadDeviceNotFound as dev_error:
        # Device not found, display error and return -1
        print('[!] WHAD device not found (are you sure `%s` is a valid device identifier ?)' % (
            args.device
        ))
        sys.exit(-1)
    except WhadDeviceNotReady as dev_busy:
        # Device not ready, display error and return -1
        print('[!] WHAD device seems busy, make sure no other program is using it.')
        sys.exit(-1)

    except KeyboardInterrupt as keybd_evt:
        if scanner is not None:
            sys.stdout.write('Stopping scanner ...')
            sys.stdout.flush()
            scanner.stop()
            scanner.close()
            sys.stdout.write(' done\n')
            sys.stdout.flush()
        if monitor is not None:
            monitor.close()
