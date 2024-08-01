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
from whad.unifying.connector import Mouse, Mouselogger, ESBAddress
from whad.unifying.stack.constants import ClickType
from whad.esb.exceptions import InvalidESBAddressException

# Logging
logger = logging.getLogger(__name__)

TOOL_DESCRIPTION="""This tool synchronizes with an existing mouse and then logs all mouse moves and
button presses or inject moves and button presses.
"""

class UniMouseApp(CommandLineSink):
    """Logitech Unifying mouse CLI app
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
            '-a',
            '--address',
            metavar='ADDRESS',
            dest='address',
            default=None,
            help="Target mouse with address ADDRESS"
        )

        # Mouse logging raw output
        self.add_argument(
            '-r',
            '--raw',
            dest='raw',
            action="store_true",
            default=False,
            help="Log mouse output in raw format"
        )

        # Mouse duplication option
        self.add_argument(
            '-d',
            '--duplicate',
            dest='duplicate',
            action='store_true',
            default=False,
            help="If set, send your current mouse moves and clicks to the target mouse dongle"
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
                    self.error("You must specify a target mouse address with -a/--address")
                else:
                    # If an address is provided, we check its format and start
                    # sniffing packets from this device
                    try:
                        # Check address format
                        addr = ESBAddress(self.args.address)

                        # If -r option is set, sync and replicate our mouse moves
                        if self.args.duplicate:
                            self.duplicate_mouse(addr)
                        else:
                            # If stdin is piped, then we expect some mouse moves and clicks
                            # coming from stdin
                            if self.is_stdin_piped():
                                self.duplicate_stdin(addr)
                            else:
                                # No action specified, simply log mouse events
                                self.log_mouse(addr)
                    except InvalidESBAddressException:
                        # Invalid device address
                        self.error('Target address does not match the expected format !')

            else:
                # Missing interface.
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt:
            self.warning('wuni-mouse stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def duplicate_mouse(self, address: ESBAddress):
        """Duplicate current mouse to the target wireless mouse dongle.
        """
        # Sync with target mouse
        connector = Mouse(self.interface)
        connector.start()
        connector.channel = 5
        connector.address =  str(address)
        connector.synchronize()

        print('Mouse found and locked, duplicating mouse moves and clicks (hit CTL-C to stop)')

        def on_move(x, y):
            """Forward captured mouse movement to target mouse.
            """
            mouse_coords = UniMouseApp.mouse_coords
            if mouse_coords is None:
                UniMouseApp.mouse_coords = (x,y)
            else:
                orig_x, orig_y = mouse_coords
                dx, dy = x - orig_x, y - orig_y
                displacement = dx*dx+dy*dy
                if displacement >= 49:
                    UniMouseApp.mouse_coords = (x,y)
                    connector.move(dx, dy)

        def on_scroll(x, y, dx, dy):
            """Forward captured wheel movement to target mouse.
            """
            if dx>0:
                connector.wheel_down()
            elif dx<0:
                connector.wheel_up()
            if dy>0:
                connector.wheel_right()
            elif dy<0:
                connector.wheel_left()

        def on_click(x, y, button, pressed):
            if button == mouse.Button.left:
                if not pressed:
                    connector.left_click()
            elif button == mouse.Button.right:
                if not pressed:
                    connector.right_click()
            elif button == mouse.Button.middle:
                if not pressed:
                    connector.middle_click()

        # Catch mouse events and dispatch to callbacks
        try:
            with mouse.Listener(
                on_move=on_move,
                on_click=on_click,
                on_scroll=on_scroll) as listener:
                listener.join()
        except KeyboardInterrupt:
            self.warning('Interrupted by user (CTL-C)')

    def duplicate_stdin(self, address: ESBAddress):
        """Duplicate stdin moves and clicks to the target wireless mouse dongle.

        Read lines from stdin and inject corresponding moves. Timing need to be
        handled bythe program sending mouse moves (and clicks) on stdin.

        Linme format is the following:

          X,Y,WHEEL_X,WHEEL_Y,BTNS

        with X and Y decimal integers representing the mouse movement, WHEEL_X
        and WHEEL_Y decimal integers representing the mouse wheel movement and
        BTNS being a series of letters ffrom "L", "R" and "M" corresponding to
        a click event to send.
        """
        # Sync with target mouse
        connector = Mouse(self.interface)
        connector.start()
        connector.channel = 5
        connector.address =  str(address)
        connector.synchronize()

        print('Mouse found and locked, sending moves received on stdin...')

        # Read lines from stdin
        for line in sys.stdin:
            try:
                move = line.split(',')
                if len(move) == 5:
                    dx,dy,wx,wy,btns = move

                    # Extract move delta
                    dx = int(dx) if len(dx) > 0 else 0
                    dy = int(dy) if len(dy) > 0 else 0
                    wx = int(wx) if len(wx) > 0 else 0
                    wy = int(wy) if len(wy) > 0 else 0

                    # Cap values ([-2047, 2047] for dx/dy and
                    # [-127,127] for wx/wy
                    if dx > 2047:
                        dx = 2047
                    elif dx < -2047:
                        dx = -2047
                    if dy > 2047:
                        dy = 2047
                    elif dy < -2047:
                        dy = -2047

                    # Send mouse move if any
                    # (0,0) means no move !
                    if dx != 0 or dy != 0:
                        connector.move(dx, dy)

                    # Send wheel moves (if any)
                    if wx > 0:
                        connector.wheel_down()
                    elif wx < 0:
                        connector.wheel_up()
                    if wy > 0:
                        connector.wheel_right()
                    elif wy < 0:
                        connector.wheel_left()

                    # Send clicks if any
                    btns = btns.upper()
                    if 'R' in btns:
                        connector.right_click()
                    if 'L' in btns:
                        connector.left_click()
                    if 'M' in btns:
                        connector.middle_click()

            except ValueError:
                self.warning('Invalid value in mouse move')

        # Wait for connector to send message
        time.sleep(1)
        connector.stop()


    def log_mouse(self, address: ESBAddress):
        """Log mouse moves and button presses.
        """
        connector = Mouselogger(self.interface)
        connector.address = str(address)
        connector.scanning = True
        connector.decrypt = True

        buttons_state = [0, 0, 0]

        connector.start()
        for delta, wheel, buttons in connector.stream():
            buttons_event = []
            # detect any button state change
            if buttons & ClickType.LEFT > 0:
                if buttons_state[0] == 0:
                    buttons_event.append("left button pressed")
                buttons_state[0] = 1
            else:
                if buttons_state[0] == 1:
                    buttons_event.append("left button released")
                buttons_state[0] = 0
            if buttons & ClickType.RIGHT > 0:
                if buttons_state[1] == 0:
                    buttons_event.append("right button pressed")
                buttons_state[1] = 1
            else:
                if buttons_state[1] == 1:
                    buttons_event.append("right button released")
                buttons_state[1] = 0
            if buttons & ClickType.MIDDLE > 0:
                if buttons_state[2] == 0:
                    buttons_event.append("middle button pressed")
                buttons_state[2] = 1
            else:
                if buttons_state[2] == 1:
                    buttons_event.append("middle button released")
                buttons_state[2] = 0

            wheel_events = []
            if wheel[0] != 0:
                wheel_events.append("wheel_x:"+str(wheel[0]))
            if wheel[1] != 0:
                wheel_events.append("wheel_y:"+str(wheel[1]))

            if len(buttons_event) > 0 or len(wheel_events) > 0:
                events = " | " + ", ".join(wheel_events + buttons_event)
            else:
                events = ""
            if not self.args.raw:
                print(f"Mouse move (dx:{delta[0]:d}, dy:{delta[1]:d}){events}")
            else:
                print(str(delta[0])+","+str(delta[1])+","+str(wheel[0])+","+str(wheel[1])+","+str(buttons))

def wuni_mouse_main():
    """Logitech Unifying mouse tool main routine.
    """
    app = UniMouseApp()
    run_app(app)
