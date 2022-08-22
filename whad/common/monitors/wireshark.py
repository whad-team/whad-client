from whad.common.monitors.pcap import PcapWriterMonitor
from whad.exceptions import ExternalToolNotFound
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen, DEVNULL
from shutil import which
from os import mkfifo

class WiresharkMonitor(PcapWriterMonitor):
    def __init__(self, monitor_reception=True, monitor_transmission=True):
        # Check if wireshark can be found:
        self._wireshark_process = None
        self._wireshark_path = which("wireshark")
        if self._wireshark_path is None:
            raise ExternalToolNotFound("wireshark")

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
