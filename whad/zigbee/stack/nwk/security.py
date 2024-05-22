from whad.zigbee.stack.nwk.exceptions import NWKInvalidKey

class NetworkSecurityMaterial:

    KEY_COUNTER = 0

    def __init__(self, key, key_sequence_number=None, outgoing_frame_counter=0):
        if isinstance(key,str):
            try:
                self.key = bytes.fromhex(key.replace(":",""))
            except ValueError:
                raise NWKInvalidKey()
        elif isinstance(key,bytes):
            self.key = key

        if len(self.key) != 16:
            raise NWKInvalidKey()

        if key_sequence_number is not None:
            self.key_sequence_number = key_sequence_number
        else:
            self.key_sequence_number = NetworkSecurityMaterial.KEY_COUNTER
            NetworkSecurityMaterial.KEY_COUNTER+=1

        self.outgoing_frame_counter = outgoing_frame_counter
        self.incoming_frame_counters = {}

    def add_incoming_frame_counter(self, device_address, frame_counter):
        self.incoming_frame_counters[device_address] = frame_counter

    def __eq__(self, other):
        return self.key == other.key

    def __repr__(self):
        printable_key = ":".join(["{:02X}".format(i) for i in self.key])
        return "NetworkSecurityMaterial(Key #{}, '{}')".format(self.key_sequence_number, printable_key)
