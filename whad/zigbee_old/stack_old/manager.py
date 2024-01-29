class Dot15d4Manager:
    def __init__(self, services={}, database=None, upper_layer=None, lower_layer=None):
        self._services = services
        self._database = database
        self._upper_layer = upper_layer
        self._lower_layer = lower_layer

    def get_service(self, service):
        if service in self._services:
            return self._services[service]
        return None

    @property
    def services(self):
        return self._services

    @property
    def database(self):
        return self._database

    @property
    def upper_layer(self):
        return self._upper_layer

    @property
    def lower_layer(self):
        return self._lower_layer

    @upper_layer.setter
    def upper_layer(self, upper_layer):
        self._upper_layer = upper_layer
