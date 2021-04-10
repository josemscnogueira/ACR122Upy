from .device.acr122u import ACR122u

a = ACR122u()
a.open()
a.info()

#with ACR122u() as a:
#    a.info()
