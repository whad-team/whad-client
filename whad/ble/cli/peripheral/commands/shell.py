"""BLE peripheral emulation interactive shell
"""
from binascii import unhexlify, Error as BinasciiError
from whad.cli.app import command
from whad.ble.cli.peripheral.shell import BlePeriphShell

def check_profile(profile):
    """Check profile validity.

    :param dict p: Profile
    :return bool: True if profile format is OK, False otherwise
    """
    # Make sure we have a 'devinfo' entry
    if 'devinfo' not in profile:
        return False

    # Make sure we have a valid adv_data entry
    if 'adv_data' not in profile['devinfo']:
        return False
    try:
        unhexlify(profile['devinfo']['adv_data'])
    except BinasciiError:
        return False

    # Make sure we have a valid scan_rsp entry (if provided)
    if 'scan_rsp' not in profile['devinfo']:
        return False
    if profile['devinfo']['scan_rsp'] is not None:
        try:
            unhexlify(profile['devinfo']['scan_rsp'])
        except BinasciiError:
            return False

    # Make sure we have a BD address
    if 'bd_addr' not in profile['devinfo']:
        return False

    # OK
    return True

@command('interactive')
def interactive_handler(app, _):
    """interactive BLE shell

    <ansicyan><b>interactive</b></ansicyan>

    Starts an interactive shell and let you create and advertise a BLE WHAD device:
    - create, list and remove services
    - create, list and remove characteristics
    - set characteristic value, send notifications/indications
    """
    # We need to have an interface specified
    if app.interface is not None:
        # If a profile has been provided, load it
        if app.args.profile is not None:
            # Read profile
            profile_json = open(app.args.profile,'rb').read()
        else:
            profile_json = None

        # Launch an interactive shell
        myshell = BlePeriphShell(app.interface, profile_json)
        myshell.run()
    else:
        app.error("You need to specify an interface with option --interface.")
