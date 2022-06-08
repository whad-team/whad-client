import os
import select
from threading import Lock
from serial import Serial

from whad.device import WhadDevice
from whad.protocol.whacky_pb2 import Message

class UartDevice(WhadDevice):
    """
    UartDevice device class.
    """

    def __init__(self, port='/dev/ttyUSB0', baudrate=115200):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target UART device in non-blocking mode
        self.__port = port
        self.__baudrate = baudrate
        self.__fileno = None
        self.__uart = None

        # Output pipe
        self.__outpipe = bytearray()
        self.__inpipe = bytearray()

        # Create lock
        self.__lock = Lock()

    def open(self):
        """
        Open device.
        """
        # Open UART device
        self.__uart = Serial(self.__port, self.__baudrate)
        # Get file number to use with select()
        self.__fileno = self.__uart.fileno()

    def write(self, data):
        """
        Add data to the output pipe.
        """
        self.__lock.acquire()
        self.__outpipe.extend(data)
        self.__lock.release()

    def close(self):
        """
        Close current device.
        """
        self.__uart.close()
        self.__uart = None
        self.__fileno = None

    def flush_pending(self):
        """
        Write pending data into our UART connection.
        """
        if self.__uart is not None:
            self.__lock.acquire()
            nb_bytes_written = os.write(self.__fileno, bytes(self.__outpipe))
            self.__outpipe = self.__outpipe[nb_bytes_written:]
            self.__lock.release()
            return nb_bytes_written
        else:
            return -1            

    def read_pending(self):
        """
        Read pending data.
        """
        return os.read(self.__fileno, 1024)

    def send_message(self, message, filter=None):
        """
        Serialize message and add it to our output pipe.
        """
        # Convert message into bytes
        raw_message = message.SerializeToString()

        # Define header
        header = [
            0xAC, 0xBE,
            len(raw_message) & 0xff,
            (len(raw_message) >> 8) & 0xff
        ]

        # Send header followed by serialized message
        self.write(header)
        self.write(raw_message)

        if filter is not None:
            result = None
            while result is None:
                result = self.process(filter)
            return result

    def on_data_received(self, data, filter=None):
        """
        Data received callback.

        This callback will process incoming messages, parse them
        and then forward to the message processing callback.
        """
        msg_result = None
        self.__inpipe.extend(data)
        if len(self.__inpipe) > 2:
            # Is the magic correct ?
            if self.__inpipe[0] == 0xAC and self.__inpipe[1] == 0xBE:
                # Have we received a complete message ?
                if len(self.__inpipe) > 4:
                    msg_size = self.__inpipe[2] | (self.__inpipe[3] << 8)
                    if len(self.__inpipe) >= (msg_size+4):
                        raw_message = self.__inpipe[4:4+msg_size]
                        _msg = Message()
                        _msg.ParseFromString(raw_message)

                        if filter is not None and not filter(_msg):
                            self.on_message_received(_msg)
                        else:
                            msg_result = _msg
                        
                        # Chomp
                        self.__inpipe = self.__inpipe[msg_size + 4:]
            else:
                # Nope, that's not a header
                while (len(self.__inpipe) >= 2):
                    if (self.__inpipe[0] != 0xAC) or (self.__inpipe[1] != 0xBE):
                        self.__inpipe = self.__inpipe[1:]
                    else:
                        break
        return msg_result


    def process(self, filter=None):
        message = None

        rlist = [self.__fileno]
        if len(self.__outpipe) > 0:
            wlist = [self.__fileno]
        else:
            wlist = []
        elist = []

        readers,writers,errors = select.select(
            rlist,
            wlist,
            elist
        )
        # Handle incoming messages if any
        if len(readers) > 0:
            data = self.read_pending()
            message = self.on_data_received(data, filter=filter)

        # Handle output messages if any
        if len(writers) > 0:
            self.flush_pending()

        # Return message if any
        if message is not None and filter is not None and filter(message):
            return message
        elif message is not None:
            return message
