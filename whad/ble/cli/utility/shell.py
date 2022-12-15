from cmd import Cmd
from prompt_toolkit import print_formatted_text, HTML
from hexdump import hexdump

from whad.ble.profile.characteristic import CharacteristicProperties

from whad.device import WhadDevice, WhadDeviceConnector
from whad.ble import Scanner, Central
from whad.ble.utils.att import UUID
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.utility.cache import BleDevicesCache

INTRO='''
 __    __ _               _ 
/ / /\ \ \ |__   __ _  __| |
\ \/  \/ / '_ \ / _` |/ _` |
 \  /\  /| | | | (_| | (_| |
  \/  \/ |_| |_|\__,_|\__,_|
                            
'''

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
        


class BleUtilityShell(Cmd):
    """Bluetooth Low Energy interactive shell
    """

    def __init__(self, interface: WhadDevice = None):
        super().__init__()

        # If interface is None, pick the first matching our needs
        self.__interface = interface
        self.__connector: WhadDeviceConnector = None
        self.__cache = BleDevicesCache()

        self.__target = None
        self.__target_bd = None

        self.intro = INTRO

        self.update_prompt()

    def update_prompt(self):
        """Update prompt to reflect current state
        """
        if not self.__target_bd:
            self.prompt = 'whad-ble> '
        else:
            self.prompt = 'whad-ble|%s> ' % self.__target_bd


    def switch_role(self, new_role):
        """Switch from current role (if any) to another role.
        """
        if self.__connector is not None:
            self.__connector.stop()
        self.__connector = new_role(self.__interface)

    def do_scan(self, args):
        """scan surrounding devices and show a small summary
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
        self.__connector.stop()

    def do_devices(self, arg):
        """list discovered devices
        """
        print_formatted_text(HTML('<ansigreen> RSSI Lvl  Type  BD Address        Extra info</ansigreen>'))
        for device in self.__cache.iterate():
            print(device['info'])

    def do_info(self, arg):
        """show detailed device information
        """
        address = arg
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

    def get_cache_targets(self):
        # Keep track of BD addresses and names
        targets = [dev['info'].address for dev in self.__cache.iterate()]
        targets.extend([dev['info'].name for dev in self.__cache.iterate() if dev['info'].name is not None])
        return targets

    def complete_info(self, text, line, begidx, endidx):
        """Autocomplete the 'info' command, providing bd addresses of discovered devices.
        """
        # Keep track of BD addresses and names
        targets = self.get_cache_targets()
        if text:
            return [
                address for address in targets
                if address.startswith(text)
            ]
        else:
            return targets

    def complete_connect(self, text, line, begidx, endidx):
        # Keep track of BD addresses and names
        targets = self.get_cache_targets()
        if text:
            return [
                address for address in targets
                if address.startswith(text)
            ]
        else:
            return targets

    def do_connect(self, arg):
        """connect to a device

        Initiate a Bluetooth Low Energy connection to a specific device by its
        Bluetooth Device address or its name. If multiple devices have the same
        name, the first one will be picked for connect.
        """
        try:
            target = self.__cache[arg]
        
            # Switch role to Central
            self.switch_role(Central)

            # Start central role
            self.__connector.start()

            # Try to connect to our target device
            self.__target = self.__connector.connect(target['info'].address)
            self.__target_bd = target['info'].address

            # Check connection is OK
            if self.__target is not None:
                print('Successfully connected to target %s' % target['info'].address)
                self.update_prompt()
            else:
                print('Unable to connect to device %s' % target['info'].address)
                self.__target_bd = None

        except IndexError as notfound:
            print('Device %s not found' % arg)

    def do_disconnect(self, arg):
        """disconnect from device
        """
        if self.__target is not None:
            self.__target.disconnect()
            self.__target_bd = None
        
        # Update prompt
        self.update_prompt()

    def do_profile(self, arg):
        """discover device services and characteristics
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

    def do_services(self, arg):
        """discover/show current device services

        This command should only be used when connected to a device, as it will
        discover its exposed primary services.
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

    def do_characteristics(self, arg):
        """discover/show current device characteristics
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
    
    def do_read(self, args):
        """read a characteristic

        This command reads the content of a GATT characteristic value or descriptor.
        """
        if self.__target_bd:
            if self.__cache.is_discovered(self.__target_bd):
                # parse target arguments
                args = list(filter(lambda x: x!='', args.split(' ')))
                if len(args) == 0:
                    self.error('You must provide at least a characteristic value handle or characteristic UUID.')
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
                        attrib = self.__target.find_object_by_handle(handle)
                        if attrib is None:
                            self.error('No characteristic found with handle %d' % handle)
                        else:
                            try:
                                # Read data
                                if offset is not None:
                                    value = attrib.read(offset=offset)
                                else:
                                    value = attrib.read()

                                # Display result as hexdump
                                hexdump(value)
                                
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
                                
                            except GattTimeoutException as timeout:
                                self.error('GATT timeout while reading.')
                        else:
                            self.error('No characteristic found with UUID %s' % handle)
            else:
                self.error('Device has not been discovered yet')
        else:
            self.error('No device connected.')


    def error(self, message):
        print_formatted_text(HTML('<b><ansired>%s</ansired></b>' % message))

    def do_help(self, arg):
        '''show this help screen
        '''
        if arg=='':
            # Show help with HTML formatted docstrings
            print_formatted_text(HTML('<ansigreen><b>Help</b></ansigreen>'))
            print('')

            # Loop on commands
            commands = []
            for prop in dir(self):
                p = getattr(self, prop)
                if callable(p) and prop.startswith('do_') and hasattr(p, '__doc__'):
                    command = prop[3:]
                    commands.append((prop[3:], p.__doc__.splitlines()[0]))
            
            # Compute the longest command
            max_cmd_size = max([len(cmd) for cmd,doc in commands])
            cmd_fmt = "<ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
            for cmd, doc in commands:
                print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))
        else:
            try:
                # Retrieve command documentation
                prop = getattr(self, 'do_'+arg)

                if hasattr(prop, '__doc__'):
                    doc = prop.__doc__.splitlines()
                    print_formatted_text(HTML('<ansicyan><b>%s</b></ansicyan> - <b>%s</b>' % (
                        arg, doc[0]
                    )))
                    if len(doc) >= 2:
                        print('')
                        for extra_line in doc[1:]:
                            print_formatted_text(HTML(extra_line.strip()))

            except AttributeError as error:
                print_formatted_text(HTML('<ansired><b>Cannot get help for an invalid command.</b></ansired>'))

    def do_quit(self, arg):
        """close whad-ble
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
