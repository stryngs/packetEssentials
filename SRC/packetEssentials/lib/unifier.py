import subprocess, time
from scapy.utils import hexstr

## Python 3 workaround
try:
    from drivers import Drivers
    from chan_freq import ChanFreq
except:
    from .drivers import Drivers
    from .chan_freq import ChanFreq

class Unify(object):
    """This class acts a singular point of contact for tracking purposes"""

    def __init__(self, nic):
        ## Discover the driver
        self.nic = nic
        cmd = 'readlink -nfqs /sys/class/net/%s/device/driver' % self.nic
        self.driver = subprocess.check_output(cmd, shell = True).split('/')[-1:][0]

        ## Notate driver offset
        self.peDrivers = Drivers()
        self.chanFreq = ChanFreq()
        self.offset = self.peDrivers.drivers(self.driver)


    def times(self):
        """Timestamp function"""
        ### This converts to Wireshark style
        #int(wepCrypto.endSwap('0x' + p.byteRip(f.notdecoded[8:], qty = 8, compress = True)), 16)
        epoch = int(time.time())
        lDate = time.strftime('%Y%m%d', time.localtime())
        lTime = time.strftime('%H:%M:%S', time.localtime())
        return epoch, lDate, lTime


    def getStats(self, pkt):
        """Returns statistics for a given packet based upon the driver in use

        Currently this function supports the following:
          - Channel
          - Frequency
          - RSSI

        If you think that this function should added to, submit a PR via github
        """
        notDecoded = hexstr(str(pkt.notdecoded), onlyhex=1).split(' ')
        try:
            chan = self.chanFreq.twoFour(int(notDecoded[self.offset] + notDecoded[self.offset - 1], 16))
        except:
            chan = -256
        try:
            freq = int(notDecoded[self.offset] + notDecoded[self.offset - 1], 16)
        except:
            freq = -256
        try:
            rssi = -(256 - int(notDecoded[self.offset + 3], 16))
        except:
            rssi = -256

        return {'chan': chan,
                'freq': freq,
                'rssi': rssi}
