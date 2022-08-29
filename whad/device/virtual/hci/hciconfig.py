from fcntl import ioctl
from socket import socket, SOCK_RAW
from struct import pack, unpack

class HCIConfig(object):
    '''
    This class allows to easily configure an HCI Interface.
    '''
    HCIDEVDOWN = 0x400448ca
    HCIDEVRESET = 0x400448cb
    HCIDEVUP = 0x400448c9
    HCIGETDEVLIST = 0x800448d2
    HCIGETDEVINFO = 0x800448d3

    @classmethod
    def list(cls):
        sock = socket(31, SOCK_RAW, 1)

        # Get number of devices
        arg = pack('I', 16) +  b"\x00" * (8*16)
        output = ioctl(sock.fileno(), cls.HCIGETDEVLIST, arg)
        number_of_devices = unpack('H', output[:2])[0]

        device_ids = []
        for device_number in range(number_of_devices):
            device_id = unpack('H', output[4 + 8*device_number:4 + 8*device_number + 2])[0]
            device_ids.insert(0, device_id)

        return device_ids

    @classmethod
    def down(cls, index):
        '''
        This class method stops an HCI interface.
        Its role is equivalent to the following command : ``hciconfig hci<index> down``

        :param index: index of the HCI interface to stop
        :type index: integer

        :Example:

        >>> HCIConfig.down(0)

        '''

        #try:
        sock = socket(31, SOCK_RAW, 1)
        ioctl(sock.fileno(), cls.HCIDEVDOWN, index)
        sock.close()
        #except IOError:
        #    return False
        return True

    @classmethod
    def reset(cls, index):
        '''
        This class method resets an HCI interface.
        Its role is equivalent to the following command : ``hciconfig hci<index> reset``

        :param index: index of the HCI interface to reset
        :type index: integer

        :Example:

        >>> HCIConfig.reset(0)

        '''
        try:
            sock = socket(31, SOCK_RAW, 1)
            ioctl(sock.fileno(), cls.HCIDEVRESET, index)
            sock.close()
        except IOError:
            return False
        return True

    @classmethod
    def up(cls, index):
        '''
        This class method starts an HCI interface.
        Its role is equivalent to the following command : ``hciconfig hci<index> up``

        :param index: index of the HCI interface to start
        :type index: integer

        :Example:

        >>> HCIConfig.up(0)

        '''
        try:
            sock = socket(31, SOCK_RAW, 1)
            ioctl(sock.fileno(), cls.HCIDEVUP, index)
            sock.close()
        except IOError:
            return False
        return True
