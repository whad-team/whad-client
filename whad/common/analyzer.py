
class TrafficAnalyzer:
    def __init__(self):
        self.reset()

    def process_packet(self, packet):
        pass

    def reset(self):
        self._triggered = False
        self._completed = False

    def trigger(self):
        self._triggered = True

    def complete(self):
        self._completed = True

    @property
    def output(self):
        return None

    @property
    def triggered(self):
        return self._triggered

    @property
    def completed(self):
        return self._completed
