"""BLE peripheral emulation interactive shell
"""
import json

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
        bytes.fromhex(profile["devinfo"]["adv_data"])
    except ValueError:
        return False

    # Make sure we have a valid scan_rsp entry (if provided)
    if 'scan_rsp' not in profile['devinfo']:
        return False
    if profile['devinfo']['scan_rsp'] is not None:
        try:
            bytes.fromhex(profile["devinfo"]["scan_rsp"])
        except ValueError:
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
            with open(app.args.profile,'rb') as f:
                profile_json = f.read()
            try:
                if not check_profile(json.loads(profile_json)):
                    app.error("Invalid JSON file (does not contain a valid GATT profile).")
                    profile_json = None
            except json.decoder.JSONDecodeError as parsing_err:
                app.error((f"Invalid JSON file, parsing error line {parsing_err.lineno}: "
                          f"{parsing_err.msg}"))
                app.exit()
        else:
            profile_json = None

        # Launch an interactive shell
        myshell = BlePeriphShell(app.interface, profile_json)
        myshell.run()
    else:
        app.error("You need to specify an interface with option --interface.")
