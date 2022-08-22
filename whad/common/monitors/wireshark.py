from whad.common.monitors.pcap import PcapWriterMonitor
from whad.exceptions import ExternalToolNotFound
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen, DEVNULL
from shutil import which
from os import mkfifo

class WiresharkMonitor(PcapWriterMonitor):
    """
    WiresharkMonitor.

    Runs a wireshark instance in background and monitor the traffic received and transmitted
    by the targeted connector. It is mainly a very basic wrapper that launches wireshark in background,
    creates a named fifo and populates it using underlying PcapWriterMonitor implementation.
    """
    def __init__(self, monitor_reception=True, monitor_transmission=True):
        self._wireshark_process = None
        # Checks the presence of wireshark
        self._wireshark_path = which("wireshark")
        if self._wireshark_path is None:
            raise ExternalToolNotFound("wireshark")
        # We create a random name for our named pipe.
        fifo_name = gettempdir()+"/" + next(_get_candidate_names()) + ".pcap"
        mkfifo(fifo_name)

        self._start_wireshark(fifo_name)
        super().__init__(
                            pcap_file=fifo_name,
                            monitor_reception=monitor_reception,
                            monitor_transmission=monitor_transmission
        )

    def _start_wireshark(self, fifo):
        self._wireshark_process = Popen([self._wireshark_path, "-k", "-i", fifo], stderr=DEVNULL, stdout=DEVNULL)

    def close(self):
        super().close()
        self._wireshark_process.terminate()
