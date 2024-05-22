from whad.common.stack import Layer

class Dot15d4Manager(Layer):
    """
    Defines a 802.15.4 manager, containing some services.
    """
    def configure(self, options={}):
        super().configure(options=options)
        self._services = {}
        self.init()

    def init(self):
        pass

    def add_service(self, service_name, service):
        self._services[service_name] = service

    def get_service(self, service):
        if service in self._services:
            return self._services[service]
        return None

    @property
    def upper_layer(self):
        for k, v in self.layers.items():
            if self.get_layer(k).parent.alias == self.alias:
                return self.get_layer(k)
        return None

    @property
    def lower_layer(self):
        return self.parent


    @property
    def database(self):
        return self.state

    @property
    def services(self):
        return self._services
