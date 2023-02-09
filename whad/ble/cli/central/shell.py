import re

from prompt_toolkit import print_formatted_text, HTML
from hexdump import hexdump
from binascii import unhexlify, Error as BinasciiError

from scapy.layers.bluetooth4LE import *

from whad.ble.exceptions import InvalidHandleValueException
from whad.exceptions import ExternalToolNotFound
from whad.device import WhadDevice, WhadDeviceConnector
from whad.ble import Scanner, Central
from whad.ble.profile.characteristic import CharacteristicProperties
from whad.ble.profile.advdata import AdvDataFieldList
from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import AttError, AttributeNotFoundError, \
    InsufficientAuthenticationError, InsufficientAuthorizationError, \
    InsufficientEncryptionKeySize, ReadNotPermittedError, \
    WriteNotPermittedError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.cache import BleDevicesCache
from whad.ble.scanning import AdvertisingDevice
from whad.common.monitors import PcapWriterMonitor, WiresharkMonitor

from whad.cli.shell import InteractiveShell, category

#import logging
#logging.basicConfig(level=logging.DEBUG)

INTRO='''
ble-central, the WHAD Bluetooth Low Energy central utility
'''

BDADDR_REGEXP = '^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$'

def show_adv_record(offset, raw_record):
    """Display advertising record as hexdump.

    @param offset int: AD record offset in AD records data
    @param raw_record bytes: Raw AD record
    """
    nlines = int(len(raw_record)/16)
    if nlines*16 < len(raw_record):
        nlines += 1
    
    print(' AD Record #%d:' % offset)
    for line in range(0, nlines):
        line_str = ' '.join(['%02x' % c for c in raw_record[line*16:(line+1)*16]])
        print('  ' + line_str)
        


class BleCentralShell(InteractiveShell):
    """Bluetooth Low Energy interactive shell
    """

    def __init__(self, interface: WhadDevice = None):
        super().__init__(HTML('<b>ble-central></b> '))

        # If interface is None, pick the first matching our needs
        self.__interface = interface
        self.__connector: WhadDeviceConnector = None
        self.__cache = BleDevicesCache()

        self.__target = None
        self.__target_bd = None
        self.__wireshark = None

        self.intro = INTRO

        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        """
        if not self.__target_bd:
            self.set_prompt(HTML('<b>ble-central></b> '), force)
        else:
            self.set_prompt(HTML('<b>ble-central|<ansicyan>%s</ansicyan>></b> ' % self.__target_bd), force)


    def switch_role(self, new_role):
        """Switch from current role (if any) to another role.
        """
        if self.__connector is not None:
            self.__connector.stop()
            if self.__wireshark is not None:
                self.__wireshark.detach()
        self.__connector = new_role(self.__interface)
        if self.__wireshark is not None:
            self.__wireshark.attach(self.__connector)
            self.__wireshark.start()

    def show_att_error(self, error: AttError):
        """Parse ATT error and show exception.
        """
        if isinstance(error, InvalidHandleValueException):
            self.error('ATT Error: wrong value handle')
        elif isinstance(error, ReadNotPermittedError):
            self.error('ATT error: read operation not allowed')
        elif isinstance(error, WriteNotPermittedError):
            self.error('ATT error: write operation not allowed')
        elif isinstance(error, InsufficientAuthenticationError):
            self.error('ATT error: insufficient authentication')
        elif isinstance(error, InsufficientAuthorizationError):
            self.error('ATT error: insufficient authorization')
        elif isinstance(error, AttributeNotFoundError):
            self.error('ATT error: attribute not found')
        elif isinstance(error, InsufficientEncryptionKeySize):
            self.error('ATT error: insufficient encryption')

    @category('Devices discovery')
    def do_scan(self, args):
        """scan surrounding devices and show a small summary

        <ansicyan><b>scan</b></ansicyan>

        Scan devices and report them in this console in real-time.
        
        The following information is provided:
         - <b>RSSI:</b> represents the strength of the signal in dBm
         - <b>Address type:</b> address is either public or random
         - <b>BD address:</b> device Bluetooth address (a.k.a MAC address)
         - <b>Extra info:</b> device name is provided in advertising packet

        You can stop a scan by hitting <b>CTL-c</b> at any time, the discovered devices are kept in
        memory and would be available in autocompletion.
        """
        # Switch role to scanner
        self.switch_role(Scanner)

        # Start scanning
        print_formatted_text(HTML('<ansigreen> RSSI Lvl  Type  BD Address        Extra info</ansigreen>'))
        self.__connector.start()
        try:
            for device in self.__connector.discover_devices():
                # Show device
                print(device)

                # Add device to cache
                self.__cache.add(device)
        except KeyboardInterrupt as keybd_int:
            print('\rScan terminated by user')

        if self.__wireshark is not None:
            self.__wireshark.detach()

        self.__connector.stop()

    @category('Devices discovery')
    def do_devices(self, arg):
        """list discovered devices

        <ansicyan><b>devices</b></ansicyan>

        List every discovered device so far, through the <ansicyan>scan</ansicyan> command.
        This command displays the content of the console device cache.
        """
        print_formatted_text(HTML('<ansigreen> RSSI Lvl  Type  BD Address        Extra info</ansigreen>'))
        for device in self.__cache.iterate():
            print(device['info'])

    @category('Devices discovery')
    def do_info(self, args):
        """show detailed device information

        <ansicyan><b>info</b> <i>[ BD address ]</i></ansicyan>

        This command displays all the information discovered when scanning a given device:
         - <b>RSSI:</b> represents the strength of the signal in dBm
         - <b>Address type:</b> address is either public or random
         - <b>BD address:</b> device Bluetooth address (a.k.a MAC address)
         - <b>All the advertising records</b> returned in advertising packets and scan responses
        """
        if len(args) >= 1:
            address = args[0]
            try:
                # Retrieve device from cache
                device = self.__cache[address]
                
                # Show detailed information about the selected device
                dev_info = device['info']

                print_formatted_text(HTML('<ansigreen><b>Device %s</b></ansigreen>' % dev_info.address))

                print_formatted_text(HTML('<b>RSSI:</b>\t\t\t%4d dBm' % dev_info.rssi))
                print_formatted_text(HTML('<b>Address type:</b>\t\t%s' % 'public' if dev_info.address_type == 0 else 'random'))
                print('')
                print_formatted_text(HTML('<ansicyan><u>Raw advertising records</u></ansicyan>\n'))
                offset = 0
                for adv_record in dev_info.adv_records:
                    show_adv_record(offset, adv_record.to_bytes())
                    offset += 1
                    print('')
            except IndexError as notfound:
                print('!!! Specified BD address has not been discovered')
        else:
            self.error('<u>info</u> requires a single parameter (device name or BD address).')

    def get_cache_targets(self):
        # Keep track of BD addresses and names
        targets = [dev['info'].address for dev in self.__cache.iterate()]
        targets.extend(['"%s"' % dev['info'].name for dev in self.__cache.iterate() if dev['info'].name is not None])
        return targets

    def complete_info(self):
        """Autocomplete the 'info' command, providing bd addresses of discovered devices.
        """
        # Keep track of BD addresses and names
        targets = self.get_cache_targets()
        completions = self.autocomplete_env(BDADDR_REGEXP)
        for address in targets:
            completions[address] = None
        return completions


    def complete_connect(self):
        # Keep track of BD addresses and names
        targets = self.get_cache_targets()
        completions = self.autocomplete_env()
        for address in targets:
            completions[address] = None
        return completions


    @category('GATT client')
    def do_connect(self, args):
        """connect to a device

        <ansicyan><b>connect</b> <i>[ BD address or device name ]</i></ansicyan>

        Initiate a Bluetooth Low Energy connection to a specific device by its
        Bluetooth Device address or its name. If multiple devices have the same
        name, the first one will be picked for connect.
        """
        if len(args) < 1:
            self.error('<u>connect</u> requires a single parameter (device name or BD address).\ntype \'help connect\' for more details.')
            return

        try:
            try:
                target = self.__cache[args[0]]
                target_bd_addr = self.__cache[args[0]]['info'].address
            except IndexError as notfound:
                # If target not in cache, we are expecting a BD address
                if re.match(BDADDR_REGEXP, args[0]):
                    target_bd_addr = args[0]
                else:
                    self.error('You must provide a valid BD address.')
                    return
        
            # Switch role to Central
            self.switch_role(Central)

            # Try to connect to our target device (central role is started here)
            self.__target = self.__connector.connect(target_bd_addr)
            self.__target_bd = target_bd_addr

            # Check connection is OK
            if self.__target is not None:
                print('Successfully connected to target %s' % target_bd_addr)

                # Attach our disconnection callback
                self.__target.set_disconnect_cb(self.on_disconnect)
                
                # Attach our wireshark monitor, if any
                if self.__wireshark is not None:
                    self.__wireshark.attach(self.__connector)

                # Detach any previous callback
                self.__connector.detach_callback(self.on_disconnect, on_reception=True, on_transmission=False)

                # Attach our packet monitor callback (to detect disconnection)
                self.__connector.attach_callback(
                    self.on_disconnect,
                    on_transmission=False,
                    on_reception=True,
                    filter=lambda pkt: pkt.haslayer(LL_TERMINATE_IND)
                )

                # Create our cached device if non-existing
                if self.__target_bd not in self.__cache:
                    self.__cache.add(AdvertisingDevice(
                        -50,
                        0,
                        self.__target_bd,
                        AdvDataFieldList()
                    ))
                
                # Update prompt
                self.update_prompt()
            else:
                print('Unable to connect to device %s' % target_bd_addr)
                self.__target_bd = None

        except IndexError as notfound:
            print('Device %s not found' % args[0])


    def on_disconnect(self, packet=None):
        """Disconnection callback

        This callback is called when a BLE peripheral disconnects our central.
        """
        # Process disconnection
        self.__target_bd = None
        if self.__target is not None:

            # detach wireshark
            if self.__wireshark is not None:
                self.__wireshark.detach()

            self.__target = None

        # Update prompt
        self.update_prompt(force=True)

        # Show disconnection
        print_formatted_text(HTML('<ansired>Peripheral has just disconnected</ansired>'))        


    @category('GATT client')
    def do_disconnect(self, arg):
        """disconnect from device

        <ansicyan><b>disconnect</b></ansicyan>

        Disconnect from current connected device, if any.
        """
        if self.__target is not None:
            self.__target.disconnect()
            self.__target_bd = None

            # detach wireshark
            if self.__wireshark is not None:
                self.__wireshark.detach()
        else:
            self.warning('not connected to a device, aborted.')
        
        # Update prompt
        self.update_prompt()


    @category('GATT client')
    def do_profile(self, args):
        """discover device services and characteristics

        <ansicyan><b>profile</b></ansicyan>

        This command performs a GATT services and characteristics discovery,
        collecting all this information and keeping it in a dedicated <b>cache</b>.

        This <b>cached information</b> is then used by commands <ansicyan>read</ansicyan>, <ansicyan>services</ansicyan>,
        and <ansicyan>characteristics</ansicyan> to speed up the process.
        
        <aaa fg="orange">Sometimes this discovery process may cause an error
        and produces incomplete information, in this case try again and cross
        fingers</aaa>
        """
        if self.__target is not None:
            try:
                self.__target.discover()

                # Cache our target with its discovered services/characteristics
                self.__cache.add_profile(self.__target_bd, self.__target)
                self.__cache.mark_as_discovered(self.__target_bd)

                # Show services and characteristics
                for service in self.__target.services():
                    print_formatted_text(HTML('<ansigreen><b>Service %s</b></ansigreen>\n' % service.uuid))
                    for charac in service.characteristics():
                        properties = charac.properties
                        charac_rights = []
                        if properties & CharacteristicProperties.READ != 0:
                            charac_rights.append('read')
                        if properties & CharacteristicProperties.WRITE != 0:
                            charac_rights.append('write')
                        if properties & CharacteristicProperties.INDICATE != 0:
                            charac_rights.append('indicate')
                        if properties & CharacteristicProperties.NOTIFY != 0:
                            charac_rights.append('notify')
                        print_formatted_text(HTML(' <b>%s</b> handle: <b>%d</b>, value handle: <b>%d</b>' % (
                            charac.uuid, charac.handle, charac.value_handle
                        )))
                        print_formatted_text(HTML('  | <ansicyan>access rights:</ansicyan> <b>%s</b>' % ', '.join(charac_rights)))
                    print('')



            except GattTimeoutException as timeout:
                print('GATT timeout occured')


    @category('GATT client')
    def do_services(self, args):
        """discover/show current device services

        <ansicyan><b>services</b></ansicyan>

        This command shows the discovered primary services of a connected BLE
        device, and <u>will only work if a device is connected</u>.
        """
        if self.__target_bd is not None:

            # Do we need to discover the services ?
            if len(list(self.__target.services())) == 0:
                self.__target.discover()
                self.__cache.mark_as_discovered(self.__target_bd)

            # We are connected to a device, list cached services
            for service in self.__target.services():
                print_formatted_text(HTML('<ansicyan><b>%s</b></ansicyan> start handle: <b>%d</b>, end handle: <b>%d</b>' % (service.uuid, service.handle, service.end_handle)))
        else:
            self.error('No device connected.')


    @category('GATT client')
    def do_characteristics(self, args):
        """discover/show current device characteristics

        <ansicyan><b>characteristics</b></ansicyan>

        This command shows the services and characteristics of the connected
        device, with their handles and properties.
        """
        if self.__target_bd is not None:

            # Do we need to discover the services ?
            if len(list(self.__target.services())) == 0:
                self.__target.discover()
                self.__cache.mark_as_discovered(self.__target_bd)

            # We are connected to a device, list cached services
            for service in self.__target.services():
                for charac in service.characteristics():
                    properties = charac.properties
                    charac_rights = []
                    if properties & CharacteristicProperties.READ != 0:
                        charac_rights.append('read')
                    if properties & CharacteristicProperties.WRITE != 0:
                        charac_rights.append('write')
                    if properties & CharacteristicProperties.INDICATE != 0:
                        charac_rights.append('indicate')
                    if properties & CharacteristicProperties.NOTIFY != 0:
                        charac_rights.append('notify')
                    print_formatted_text(HTML(' <b>%s</b> handle: <b>%d</b>, value handle: <b>%d</b>' % (
                        charac.uuid, charac.handle, charac.value_handle
                    )))
                    print_formatted_text(HTML('  | <ansicyan>access rights:</ansicyan> <b>%s</b>' % ', '.join(charac_rights)))
        else:
            self.error('No device connected.')
    
    @category('GATT client')
    def do_read(self, args):
        """read a GATT attribute

        <ansicyan><b>read</b> <i>[UUID | handle] ([offset])</i></ansicyan>

        Read an attribute identified by its handle, or read the value of a characteristic
        identified by its UUID (if unique). An optional offset can be provided
        to start reading from the specified byte position (it will issue a
        <i>ReadBlob</i> operation).

        Result is displayed as an hexadecimal dump with corresponding ASCII text:

        > read 41
        00000000: 74 68 69 73 20 69 73 20  61 20 74 65 73 74        this is a test

        """
        if self.__target_bd:
            # parse target arguments
            if len(args) == 0:
                self.error('You must provide at least a characteristic value handle or characteristic UUID.')
                return
            else:
                handle = None
                offset = None
                uuid = None

            # figure out what the handle is
            if args[0].lower().startswith('0x'):
                try:
                    handle = int(args[0].lower(), 16)
                except ValueError as badval:
                    self.error('Wrong handle: %s' % args[0])
                    return
            else:
                try:
                    handle = int(args[0])
                except ValueError as badval:
                    try:
                        handle = UUID(args[0].replace('-',''))
                    except:
                        self.error('Wrong UUID: %s' % args[0])
                        return

            # Check offset and length
            if len(args) >= 2:
                try:
                    offset = int(args[1])
                except ValueError as badval:
                    self.error('Wrong offset value, will use 0 instead.')
                    offset = None
                
            # Perform characteristic read by handle
            if not isinstance(handle, UUID):
                try:
                    value = self.__target.read(handle, offset=offset)

                    # Display result as hexdump
                    hexdump(value)
                except AttError as att_err:
                    self.show_att_error(att_err)
                except GattTimeoutException as timeout:
                    self.error('GATT timeout while reading.')

            else:
                # Perform discovery if required
                if not self.__cache.is_discovered(self.__target_bd):
                    self.__target.discover()
                    self.__cache.mark_as_discovered(self.__target_bd)

                # Search characteristic from its UUID
                target_charac = self.__target.find_characteristic_by_uuid(handle)                       
                if target_charac is not None:
                    try:
                        # Read data
                        if offset is not None:
                            value = target_charac.read(offset=offset)
                        else:
                            value = target_charac.read()

                        # Display result as hexdump
                        hexdump(value)
                    
                    except AttError as att_err:
                        self.show_att_error(att_err)
                    except GattTimeoutException as timeout:
                        self.error('GATT timeout while reading.')
                else:
                    self.error('No characteristic found with UUID %s' % handle)
        else:
            self.error('No device connected.')

    def perform_write(self, args, without_response=False):
        """Perform attribute/handle characteristic
        """
        # parse target arguments
        if len(args) <2:
            self.error('You must provide at least a characteristic value handle or characteristic UUID, and a value to write.')
            return
        else:
            handle = None
            offset = None
            uuid = None

        # Figure out what the handle is
        if args[0].lower().startswith('0x'):
            try:
                handle = int(args[0].lower(), 16)
            except ValueError as badval:
                self.error('Wrong handle: %s' % args[0])
                return
        else:
            try:
                handle = int(args[0])
            except ValueError as badval:
                try:
                    handle = UUID(args[0].replace('-',''))
                except:
                    self.error('Wrong UUID: %s' % args[0])
                    return

        # Do we have hex data ?
        if args[1].lower() == 'hex':
            # Decode hex data
            hex_data = ''.join(args[2:])
            try:
                char_value = unhexlify(hex_data.replace('\t',''))
            except BinasciiError as err:
                self.error('Provided hex value contains non-hex characters.')
                return
        else:
            char_value = args[1]

        if not isinstance(char_value, bytes):
            char_value = bytes(char_value,'utf-8')
            
        # Perform ATT write by handle
        if not isinstance(handle, UUID):
            try:
                if without_response:
                    self.__target.write_command(handle, char_value)
                else:
                    self.__target.write(handle, char_value)
            except AttError as att_err:
                self.show_att_error(att_err)
            except GattTimeoutException as timeout:
                self.error('GATT timeout while writing.')
        else:
            # Perform discovery if required
            if not self.__cache.is_discovered(self.__target_bd):
                self.__target.discover()
                self.__cache.mark_as_discovered(self.__target_bd)

            # Search characteristic from its UUID
            target_charac = self.__target.find_characteristic_by_uuid(handle)                       
            if target_charac is not None:
                try:
                    if without_response:
                        target_charac.write(char_value, without_response=True)
                    else:
                        target_charac.value = char_value
                except AttError as att_err:
                    self.show_att_error(att_err)
                except GattTimeoutException as timeout:
                    self.error('GATT timeout while writing.')
            else:
                self.error('No characteristic found with UUID %s' % handle)


    @category('GATT client')
    def do_writecmd(self, args):
        """write data to a GATT attribute without waiting for a response.

        <ansicyan><b>writecmd</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

        Write data to the specified GATT attribute (identified by its handle) or to
        a characteristic value (identified by its UUID, if unique) without waiting
        for a response.

        Data can be provided hex-encoded if prefixed by "hex":

        > writecmd 41 hex 41 42 43

        The command above will write 'ABC' to attribute identified by the handle 41.
        
        Data can also be provided as text:

        > writecmd 41 ABC
        """
        if self.__target_bd:
            self.perform_write(args, without_response=True)
        else:
            self.error('No device connected.')  


    @category('GATT client')
    def do_write(self, args):
        """write data to a a GATT attribute.

        <ansicyan><b>write</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

        Write data to the specified GATT attribute (identified by its handle) or to
        a characteristic value (identified by its UUID, if unique).

        Data can be provided hex-encoded if prefixed by "hex":

        > write 41 hex 41 42 43

        The command above will write 'ABC' to attribute identified by the handle 41.
        
        Data can also be provided as text:

        > write 41 ABC

        """
        if self.__target_bd:
            self.perform_write(args, without_response=False)
        else:
            self.error('No device connected.')


    @category('GATT client')
    def do_pdu(self, args):
        """Send raw PDU to a connected device

        <ansicyan><b>pdu</b> <i>[PDU (hex)]</i></ansicyan>

        Send a raw link-layer PDU to the target device:

        > pdu 03 02 02 03

        The command above will send a <i>LL_TERMINATE_IND</i> control PDU to
        the device.

        """
        if self.__target_bd:
            try:
                if len(args) >= 1:
                    hex_value = ''.join(args)
                    raw_pdu = unhexlify(hex_value.replace(' ',''))
                    res = self.__connector.send_pdu(
                        BTLE_DATA(raw_pdu),
                        conn_handle=self.__target.conn_handle
                    )
                    if not res:
                        self.error('An error occured while sending PDU.')
                else:
                    self.error('Invalid hex value.')
            except BinasciiError as err:
                self.error('Invalid hex value.')
        else:
            self.error('No device connected.')


    @category('GATT client')
    def do_sub(self, args):
        """subscribe to a characteristic

        <ansicyan><b>sub</b> <i>[UUID | handle]</i></ansicyan>

        Subscribe to characteristic notifications/indications, based on a GATT
        characteristic handle or UUID (if unique).

        Once subscribed, notifications and indications will be displayed in the
        console.

        > sub 41
        """
        if self.__target_bd:
            # Figure out what the handle is
            if args[0].lower().startswith('0x'):
                try:
                    handle = int(args[0].lower(), 16)
                except ValueError as badval:
                    self.error('Wrong handle: %s' % args[0])
                    return
            else:
                try:
                    handle = int(args[0])
                except ValueError as badval:
                    try:
                        handle = UUID(args[0].replace('-',''))
                    except:
                        self.error('Wrong UUID: %s' % args[0])
                        return

            # If UUID is provided
            if isinstance(handle, UUID):
                target_charac = self.__target.find_characteristic_by_uuid(handle)      

                def on_charac_notified(charac, value, indication):
                    if indication:
                        print_formatted_text(HTML(
                            '<ansimagenta>Indication</ansimagenta> received from characteristic with handle %d' % (
                                charac.handle
                            )
                        ))
                        hexdump(value)
                    else:
                        print_formatted_text(HTML(
                            '<ansimagenta>Notification</ansimagenta> received from characteristic with handle %d' % (
                                charac.handle
                            )
                        ))
                        hexdump(value)
            
                if target_charac is not None:
                    try:
                        if not target_charac.must_notify():
                            if target_charac.must_indicate():
                                target_charac.subscribe(
                                    indication=True,
                                    callback=on_charac_notified
                                )
                            else:
                                self.error('Characteristic does not send notification nor indication.')
                        else:
                            target_charac.subscribe(
                                callback=on_charac_notified
                            )
                    except AttError as att_err:
                        self.show_att_error(att_err)
                    except GattTimeoutException as timeout:
                        self.error('GATT timeout while writing.')
                else:
                    self.error('No characteristic found with UUID %s' % handle)

        else:
            self.error('No device connected.')

    @category('GATT client')
    def do_unsub(self, args):
        """unsubscribe from a characteristic

        <ansicyan><b>sub</b> <i>[UUID | handle]</i></ansicyan>

        Unsubscribe to characteristic notifications/indications, based on a GATT
        characteristic handle or UUID (if unique).

        Once unsubscribed, no more notifications and indications will be displayed in the
        console.
        
        Example:

        > unsub 41
        """
        if self.__target_bd:
            # Figure out what the handle is
            if args[0].lower().startswith('0x'):
                try:
                    handle = int(args[0].lower(), 16)
                except ValueError as badval:
                    self.error('Wrong handle: %s' % args[0])
                    return
            else:
                try:
                    handle = int(args[0])
                except ValueError as badval:
                    try:
                        handle = UUID(args[0].replace('-',''))
                    except:
                        self.error('Wrong UUID: %s' % args[0])
                        return

            # If UUID is provided
            if isinstance(handle, UUID):
                target_charac = self.__target.find_characteristic_by_uuid(handle)      
            
                if target_charac is not None:
                    try:
                        target_charac.unsubscribe()
                    except AttError as att_err:
                        self.show_att_error(att_err)
                    except GattTimeoutException as timeout:
                        self.error('GATT timeout.')
                else:
                    self.error('No characteristic found with UUID %s' % handle)

        else:
            self.error('No device connected.')

    def complete_wireshark(self):
        """Autocomplete wireshark command
        """
        completions = {}
        if self.__wireshark is not None:
            completions['off'] = {}
        else:
            completions['on'] = {}
        return completions


    @category('Monitoring')
    def do_wireshark(self, arg):
        """launch wireshark to monitor packets

        <ansicyan><b>wireshark</b> <i>["on" | "off"]</i></ansicyan>

        This command launches a wireshark that will display all the packets sent
        and received in the active connection. 
        """
        if len(arg) >=1:
            enabled = arg[0].lower()=="on"
            if enabled:
                if self.__wireshark is None:
                    try:
                        self.__wireshark = WiresharkMonitor()
                        if self.__connector is not None:
                            self.__wireshark.attach(self.__connector)
                            self.__wireshark.start()
                    except ExternalToolNotFound as notfound:
                        self.error('Cannot launch Wireshark, please make sure it is installed.')
                else:
                    self.error('Wireshark is already launched, see <ansicyan>wireshark off</ansicyan>')
            else:
                # Detach monitor if any
                if self.__wireshark is not None:
                    self.__wireshark.detach()
                    self.__wireshark.close()
                    self.__wireshark = None
        else:
            self.error('Missing arguments, see <ansicyan>help wireshark</ansicyan>.')


    @category('GATT client')
    def do_mtu(self, arg):
        """set ATT MTU

        <ansicyan><b>mtu</b> <i>[MTU]</i></ansicyan>

        Set ATT MTU to <i>MTU</i>. <i>MTU</i> must be an integer value.
        """
        if self.__target_bd:
            # check MTU
            if len(arg) >= 1:
                # parse mtu
                try:
                    mtu = int(arg[0])
                    try:
                        self.__target.set_mtu(mtu)
                    except AttError as att_err:
                        self.show_att_error(att_err)
                    except GattTimeoutException as timeout:
                        self.error('GATT timeout while exchanging new MTU.')
                except ValueError as err:
                    self.error('Provided MTU is not a valid decimal integer.')
            else:
                self.error('You must provide the MTU parameter (integer value).')
        else:
            self.error('Not connected to a remote device.')


    def do_quit(self, arg):
        """close ble-central
        """
        if self.__target_bd is not None:
            self.__target.disconnect()
        if self.__connector is not None:
            self.__connector.stop()
        if self.__interface is not None:
            self.__interface.close()
        return True

    def do_exit(self, arg):
        """alias for <ansicyan>quit</ansicyan>
        """
        return self.do_quit(arg)
