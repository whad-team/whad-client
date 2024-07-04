import json
from argparse import Namespace
from prompt_toolkit import print_formatted_text, HTML
from whad.hub.ble.bdaddr import BDAddress
from whad.ble import Central
from whad.ble.stack.att.exceptions import AttError, AttributeNotFoundError, \
    InsufficientAuthenticationError, InsufficientAuthorizationError, \
    InsufficientEncryptionKeySize, ReadNotPermittedError, \
    WriteNotPermittedError, InvalidHandleValueError

def show_att_error(app, error: AttError):
    """Parse ATT error and show exception.
    """
    if isinstance(error, InvalidHandleValueError):
        app.error('ATT Error: wrong value handle')
    elif isinstance(error, ReadNotPermittedError):
        app.error('ATT error: read operation not allowed')
    elif isinstance(error, WriteNotPermittedError):
        app.error('ATT error: write operation not allowed')
    elif isinstance(error, InsufficientAuthenticationError):
        app.error('ATT error: insufficient authentication')
    elif isinstance(error, InsufficientAuthorizationError):
        app.error('ATT error: insufficient authorization')
    elif isinstance(error, AttributeNotFoundError):
        app.error('ATT error: attribute not found')
    elif isinstance(error, InsufficientEncryptionKeySize):
        app.error('ATT error: insufficient encryption')


def set_bd_address(app, central: Central):
    """Set central BLE address
    """
    bd_addr = None
    is_public = False

    # If a spoofed address has been provided, then try to set it
    if app.args.bdaddr_pub_src is not None:
        # Make sure it is a valid BD address
        if BDAddress.check(app.args.bdaddr_pub_src):
            bd_addr = app.args.bdaddr_pub_src
            is_public = True
    elif app.args.bdaddr_rand_src is not None:
        # Make sure it is a valid BD address
        if BDAddress.check(app.args.bdaddr_rand_src):
            bd_addr = app.args.bdaddr_rand_src
            is_public = False

    # Set the BD address
    if central.set_bd_address(bd_addr, public=is_public):
        print_formatted_text(HTML('BLE source address set to <b>%s</b>' % app.args.bdaddr_src.lower()))
    else:
        app.warning('Cannot spoof BD address, please make sure your WHAD interface supports this feature.')


def create_central(app, piped=False):
    central = None
    profile_loaded = False

    # Is app stdin piped ?
    if piped:
        # Create connection structure
        initiator = BDAddress(str(app.args.initiator_bdaddr), addr_type=int(app.args.initiator_addrtype))
        advertiser = BDAddress(str(app.args.initiator_bdaddr), addr_type=int(app.args.initiator_addrtype))
        existing_connection = Namespace(
            initiator=initiator.value,
            init_addr_type=int(app.args.initiator_addrtype),
            advertiser=advertiser.value,
            adv_addr_type=int(app.args.target_addrtype),
            conn_handle=int(app.args.conn_handle)
        )

        # Create central and populate GATT profile if required
        if app.args.profile is not None:
            # Load profile
            try:
                # Load file content
                profile_json = open(app.args.profile,'rb').read()
                profile = json.loads(profile_json)

                # Create central with GATT profile information and current
                # connection information
                central = Central(app.input_interface, existing_connection, from_json=profile_json)

                # Profile has been successfully loaded from JSON
                profile_loaded = True
            except IOError as err:
                app.error('Cannot access profile file (%s)' % app.args.profile)
            except Exception as err:
                app.error('Cannot parse profile file (%s)' % app.args.profile)
        else:
            # No GATT profile, create a classic Central connector with current
            # connection information
            central = Central(app.input_interface, existing_connection)
    else:
        if app.args.profile is not None:
            # Load profile
            try:
                # Load file content
                profile_json = open(app.args.profile,'rb').read()
                profile = json.loads(profile_json)

                # Create Central connector with provided GATT profile
                central = Central(app.interface, from_json=profile_json)

                # Set source BD address if required
                if app.args.bdaddr_pub_src is not None or app.args.bdaddr_rand_src is not None:
                    set_bd_address(app, central)

                # Profile has been successfully loaded from JSON
                profile_loaded = True
            except IOError as err:
                app.error('Cannot access profile file (%s)' % app.args.profile)
            except Exception as err:
                app.error('Cannot parse profile file (%s)' % app.args.profile)
        else:
            # Create classic Central connector
            central = Central(app.interface)

            # Set source BD address if required
            if app.args.bdaddr_pub_src is not None or app.args.bdaddr_rand_src is not None:
                set_bd_address(app, central)


    return (central, profile_loaded)
