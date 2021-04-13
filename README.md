# Work in Process...


## Problem with unlisted (empty) device on Linux

```
sudo nfc-scan-device -v
nfc-scan-device uses libnfc 1.7.1
1 NFC device(s) found:
error	libnfc.driver.acr122_usb	Unable to set alternate setting on USB interface (Connection timed out)
nfc_open failed for acr122_usb:001:007
```

try

```
cat /etc/modprobe.d/blacklist-libnfc.conf
blacklist nfc
blacklist pn533
blacklist pn533_usb
```

```
reboot
sudo modprobe -r pn533_usb
sudo modprobe -r pn533
sudo modprobe -r nfc
```

## Needed driver
```
sudo apt install -y pcscd libacsccid1
```

## Needed packages for pyscard:
```
    sudo apt install -y swig libpcsclite-dev
```
