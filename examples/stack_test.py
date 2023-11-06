from whad.common.stack import Layer, alias, source
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
import sys

@alias('phy')
class A(Layer):
    pass

@alias('ll')
class B(Layer):
    def show(self):
        print(self.get_layer('app'))
        self.send('app', tag='connect')

@alias('app')
class C(Layer):
    @source('ll', 'connect')
    def on_connect(self ):
        print("on connect")

A.add(B)
#A.add(C)

if __name__ == '__main__':
    a = A()
    a.get_layer('ll').show()
    input()
