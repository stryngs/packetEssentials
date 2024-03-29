import fcntl, os, struct

class Tap(object):
    """Generate and handle a tap interface"""
    __slots__ = ('nic',
                 'tapName')

    def __init__(self, tapNum = 0):
        self.tapName = 'tap' + str(tapNum)
        self.create()


    def create(self):
        """Create the tap interface"""
        self.nic = os.open('/dev/net/tun', os.O_RDWR)
        fcntl.ioctl(self.nic, 0x400454ca, struct.pack("16sH", self.tapName, 2))
