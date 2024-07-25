from whad.common.monitors.pcap import PcapWriterMonitor
from whad.exceptions import ExternalToolNotFound
from whad.esb.connector import ESB
from whad.unifying.connector import Unifying
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen, DEVNULL
import whad

from shutil import which
from os import mkfifo, unlink
from os.path import dirname, realpath, exists
from time import sleep

class WiresharkMonitor(PcapWriterMonitor):
    """
    WiresharkMonitor.

    Runs a wireshark instance in background and monitor the traffic received and transmitted
    by the targeted connector. It is mainly a very basic wrapper that launches wireshark in background,
    creates a named fifo and populates it using underlying PcapWriterMonitor implementation.
    """

    @classmethod
    def get_dissector(cls, dissector_name):
        return realpath("{}/../ressources/wireshark/{}.lua".format(dirname(whad.__file__), dissector_name))

    @classmethod
    def get_dlt(cls, domain):
        dlt = None
        return dlt

    def __init__(self, monitor_reception=True, monitor_transmission=True):
        self._wireshark_process = None
        # Checks the presence of wireshark
        self._wireshark_path = which("wireshark")
        if self._wireshark_path is None:
            raise ExternalToolNotFound("wireshark")
        # We create a random name for our named pipe.
        self.fifo_name = gettempdir()+"/" + next(_get_candidate_names()) + ".pcap"
        mkfifo(self.fifo_name)

        self.dissector = None
        super().__init__(
                            pcap_file=self.fifo_name,
                            monitor_reception=monitor_reception,
                            monitor_transmission=monitor_transmission
        )

    def attach(self, connector):
        """Attach to connector
        """
        if connector.domain in ("esb", "unifying"):
            self.dissector = WiresharkMonitor.get_dissector("esb")
        return super().attach(connector)

    def setup(self):
        self._start_wireshark(self.fifo_name, self.dissector)
        super().setup()

    def _start_wireshark(self, fifo, dissector=None):
        if dissector is None:
            self._wireshark_process = Popen([self._wireshark_path, "-k", "-i", fifo], stderr=DEVNULL, stdout=DEVNULL)
        else:
            with open(dissector, "r") as f:
                conf_line = [line for line in f.readlines() if "Proto(" in line][0]
                dissector_name = conf_line.split("Proto(")[1].split(",")[0].replace("\"", "")
            self._wireshark_process = Popen([self._wireshark_path,"-X","lua_script:"+dissector,"-o","uat:user_dlts:\"User 1 (DLT=148)\",\""+dissector_name+"\",\"\",\"\",\"\",\"\"", "-k", "-i", fifo], stderr=DEVNULL, stdout=DEVNULL)

    def close(self):
        self._writer_lock.acquire()
        if hasattr(self, "_writer") and self._writer is not None:


            # Close writer
            try:
                self._writer.close()

            except BrokenPipeError:
                pass

            # Mark writer as not available anymore
            self._writer = None

        # Release lock on writer
        self._writer_lock.release()

        if self._wireshark_process is not None:
            self._wireshark_process.terminate()
        if exists(self.fifo_name):
            unlink(self.fifo_name)
