from whad.zigbee.connector.enddevice import EndDevice

def create_enddevice(app, piped=False):
    enddevice = None
    # Is app stdin piped ?
    if piped:
        pass

    else:
        enddevice = EndDevice(app.interface)
    print("create enddevice")
    return (enddevice, None)
