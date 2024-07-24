
class TrafficAnalyzer:
    def __init__(self):
        self.reset()
        self._marked_packets = []

    def process_packet(self, packet):
        pass

    def mark_packet(self, pkt):
        self._marked_packets.append(pkt)

    def reset(self):
        self._triggered = False
        self._completed = False
        self._marked_packets = []

    def trigger(self):
        self._triggered = True

    def complete(self):
        self._completed = True

    @property
    def marked_packets(self):
        return self._marked_packets
        
    @property
    def output(self):
        return None

    @property
    def triggered(self):
        return self._triggered

    @property
    def completed(self):
        return self._completed
