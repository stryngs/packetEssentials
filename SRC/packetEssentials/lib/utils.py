from .converter import Converter
from scapy.layers.dot11 import Dot11
from scapy.utils import hexstr, PcapReader, PcapWriter, rdpcap, wrpcap
from scapy.plist import PacketList
from zlib import crc32
import binascii
import sys
import textwrap

class Poption(object):
    """Class to deal with packet specific options"""
    __slots__ = ('cv',
                 'nonceDict',
                 'verbose')

    def __init__(self):
        self.nonceDict = {'8a': 'a1',
                          '0a': 'a2',
                          'ca': 'a3',
                          '89': 't1',
                          '09': 't2',
                          'c9': 't3',
                          '8A': 'a1',
                          '0A': 'a2',
                          'CA': 'a3',
                          'C9': 't3'}
        self.verbose = False
        self.cv = Converter()


    def byteRip(self,
                stream,
                chop = False,
                compress = False,
                order = 'first',
                output = 'hex',
                qty = 0):
        """Take a packet and grab a grouping of bytes, based on what you want

        byteRip can accept a scapy object or a scapy object in str() format
        Allowing byteRip to accept str() format allows for byte insertion

        Example of scapy object definition:
          - stream = Dot11WEP()

        Example of scapy object in str() format
          - stream = str(Dot11WEP())

        chop is the concept of removing the qty based upon the order
        compress is the concept of removing unwanted spaces
        order is concept of give me first <qty> bytes or gives me last <qty> bytes
        output deals with how the user wishes the stream to be returned
        qty is how many bytes to remove
        """

        def pktFlow(pkt, output):
            if output == 'hex':
                return pkt
            if output == 'str':
                return binascii.unhexlify(str(pkt).replace(' ', ''))

        ## Python 2x and 3x seem to align on this method now
        # stream = hexstr(str(stream), onlyhex = 1)
        stream = hexstr(stream, onlyhex = 1)
        streamList = stream.split(' ')
        streamLen = len(streamList)

        ## Deal with first bytes
        if order == 'first':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[0:qty]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[qty:]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[0:qty]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[qty:]).replace(' ', ''), output)

        ## Deal with last bytes
        if order == 'last':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[streamLen - qty:]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[:-qty]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[streamLen - qty:]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[:-qty]).replace(' ', ''), output)


    def bytesCompare(self, xList, yList):
        """Compare two lists of bytes and show the deltas as such:
            <index of lists delta>: <x from xList> -- <y from yList>

        bytesCompare(
                     hexstr(xObj, onlyhex = 1).split(),
                     hexstr(yObj, onlyhex = 1).split()
                    )
        """
        for iVal, (x, y) in enumerate(zip(xList, yList)):
            if x != y:
                print('{0}: {1} -- {2}'.format(iVal, x, y))
        print('\n{0} -- {1}'.format(len(xList), len(yList)))


    def crcShave(self, sObj, shaveLeft = True, swVal = False):
        """Given a scapy object, iterate through all possible crc32 values
        Shave from left to right by default
        Calculate the CRC32 until there are no more bytes
        Returns True and stops if swVal is found

        Useful for throwing things against a wall and seeing what sticks

        If you know the scapy/wireshark version of the FCS you are hunting, use the
        swVal.  As an example --> crcShave(sObj, swVal = '0x153e3ebd')

        If you want to shave the bytes from right to left, shaveLeft = False

        Don't forget to remove the FCS bytes on the end of a frame before using, if
        those bytes are the FCS you hunt.

        Example usage as a simple function:
        import binascii
        import packetEssentials as PE
        from scapy.all import *
        from textwrap import wrap
        p = RadioTap(binascii.unhexlify('00 00 38 00 2F 40 40 A0 20 08 00 A0 20 08 00 00 20 33 7B CD 04 00 00 00 10 0C 9E 09 C0 00 A7 00 00 00 00 00 00 00 00 00 61 32 7B CD 00 00 00 00 16 00 11 03 A7 00 A3 01 C4 00 32 05 E0 3E 44 08 00 00 BD 3E 3E 15'.replace(' ', '')))
        swVal = hex(p[Dot11FCS].fcs)
        btVal = ' '.join(wrap(PE.pt.endSwap(swVal).upper()[2:], 2))                 ## Useful to know for Endianness
        lbVal = PE.pt.byteRip(p, output = 'hex', qty = 4, order = 'last')
        choppedP = PE.pt.byteRip(p, chop = True, output = 'str', qty = 4, order = 'last')
        x = PE.pt.crcShave(choppedP, swVal = swVal, shaveLeft = False)
        print(x)
        """
        if shaveLeft is True:
            dir = 'first'
        else:
            dir = 'last'
        for n in range(len(sObj)):
            ourByte = self.byteRip(sObj, order = dir, chop = True, output = 'str', qty = n)
            ourCrc = crc32(ourByte)
            ourHex = hex(0xffffffff & ourCrc)
            print('{0} --> {1} {2}'.format(n, ourHex, hexstr(ourByte, onlyhex = 1)))

            ## Check sw
            if hex(crc32(self.byteRip(sObj, chop = True, output = 'str', qty = n))) == swVal:
                return True
        return False


    def endSwap(self, value):
        """Takes an object and reverse Endians the bytes

        Useful for crc32 within 802.11:
        Autodetection logic built in for the following situations:
        Will take the stryng '0xaabbcc' and return string '0xccbbaa'
        Will take the integer 12345 and return integer 14640
        Will take the bytestream string of 'aabbcc' and return string 'ccbbaa'
        """
        try:
            value = hex(value).replace('0x', '')
            sType = 'int'
        except:
            if '0x' in value:
                sType = 'hStr'
            else:
                sType = 'bStr'
            value = value.replace('0x', '')

        start = 0
        end = 2
        swapList = []
        # print(value)
        # for i in range(len(value) / 2):
        for i in range(int(len(value) / 2)):  # Python3x compat.
            swapList.append(value[start:end])
            start += 2
            end += 2
        swapList.reverse()
        s = ''
        for i in swapList:
            s += i

        if sType == 'int':
            s = int(s, 16)
        elif sType == 'hStr':
            s = '0x' + s
        return s


    def fcsGen(self,
               ourObj,
               output = 'bytes'):
        """Return the FCS for a given set of bytes

        If you want to chop bytes for calculation, leverage self.byteRip():
            fcsGen(self.byteRip(ourObj, chop = True, output = 'str')

        Works with native scapy object, or the str() style representation of bytes
        """
        if type(ourObj) != str:
            sObj = binascii.unhexlify(hexstr(ourObj, onlyhex = 1).replace(' ', ''))
        else:
            sObj = ourObj

        frame = crc32(sObj) & 0xffffffff
        fcs = hex(frame).replace('0x', '')
        while len(fcs) < 0:                                                     ## I forget why we do this
            fcs = '0' + fcs
        fcs = self.endSwap(fcs)
        if output == 'bytes':
            return fcs
        elif output == 'str':
            return binascii.unhexlify(fcs)
        else:
            return fcs


    def macFilter(self, mac, pkt):
        """ Combo whitelist and blacklist for given MAC address """
        try:
            ## Get state
            if pkt[Dot11].addr1 == mac or pkt[Dot11].addr2 == mac or pkt[Dot11].addr3 == mac or pkt[Dot11].addr4 == mac:
                return True
            else:
                return False
        except:
            return False


    def macPair(self, macX, macY, pkt):
        """Pair up the MAC addresses, and follow them

        macX is weighted before macY, allowing the user to have a ranked format
        For fastest results, use macX as the quietest MAC
        """
        if self.macFilter(macX, pkt) is True:
            if self.macFilter(macY, pkt) is True:
                return True
        return False


    def nthBitSet(self, integer, bit):
        """Determine if the nth bit is set on a given integer.
        The first bit is considered the zeroth bit.  stdout is the decimal value
        of the bit you turn on with this method, it also returns a True.
        Using the Python bitwise operator for AND, &.

        Give it a number, it will let you know if the binary on the specified
        bit from right to left is a 1 (True) or a 0 (False).
        """
        if integer & (1 << bit):
            return True
        return False


    def symStryngs(self, scpObj, fld, maxInt = 254):
        """Iterator to show the available opcodes for a given scapy object
        Returns a list object by default of 0-253 for the opcode
        """
        count = 0
        scpObj = scpObj.copy()
        scpObj.setfieldval(fld, count)
        strDict = {}
        while count < maxInt:
            strDict.update({count: self.cv.symString(scpObj, fld)})
            count += 1
            try:
                scpObj.setfieldval(fld, count)
            except Exception as e:
                print(str(e) + ' -- Stopped on {0}'.format(count))
        return strDict
