from whad.ble import BDAddress, AdvDataFieldList, \
    AdvCompleteLocalName, AdvDataError, AdvDataFieldListOverflow, \
    AdvShortenedLocalName

from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_ADV_NONCONN_IND, \
    BTLE_ADV_DIRECT_IND, BTLE_SCAN_RSP, BTLE_ADV

class AdvertisingDevice(object):
    """Store information about a device
    """

    def __init__(self, rssi, address_type, bd_address, adv_data, undirected=True, connectable=True):
        self.__address_type = address_type
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
    def address_type(self):
        return self.__address_type

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

        # Display address type
        if self.__address_type == 0:
            addrtype = '[PUB]'
        else:
            addrtype = '[RND]'

        # Generate device summary
        return '[%4d dBm] %s %s %s' % (
            self.__rssi,
            addrtype,
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


class AdvertisingDevicesDB(object):
    """Bluetooth Low Energy devices database.

    This class stores information about discovered devices.
    """

    def __init__(self):
        self.reset()

    def reset(self):
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
        addr_type = adv_packet.getlayer(BTLE_ADV).TxAdd

        if adv_packet.haslayer(BTLE_ADV_IND):
            bd_address = BDAddress(adv_packet[BTLE_ADV_IND].AdvA)
            try:
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = AdvertisingDevice(
                    rssi,
                    addr_type,
                    bd_address,
                    adv_list
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    return device
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass

        elif adv_packet.haslayer(BTLE_ADV_NONCONN_IND):
            try:
                bd_address = BDAddress(adv_packet[BTLE_ADV_NONCONN_IND].AdvA)
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_NONCONN_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = AdvertisingDevice(
                    rssi,
                    addr_type,
                    bd_address,
                    adv_list,
                    connectable=False
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    return device
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
                        return device
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass
