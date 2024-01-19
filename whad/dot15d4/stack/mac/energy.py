class EDMeasurement:
    """
    Maximum measurement of an energy detection scan.
    """
    def __init__(self, samples, channel_page, channel):
        self.max_sample = max(samples)
        self.channel_number = channel
        self.channel_page = channel_page

    def __repr__(self):
        return ("EDMeasurement("+
                "max_sample=" + str(self.max_sample) +", "
                "channel_page=" + str(self.channel_page)+", "
                "channel_number=" + str(self.channel_number) +
            ")"
        )
