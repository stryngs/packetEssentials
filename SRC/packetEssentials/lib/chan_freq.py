class ChanFreq(object):
    """This class is for channel/frequency specific tasks"""
    __slots__ = tuple()

    def twoFour(self, val):
        """Frequency to Channel converter for 2.4 ghz"""
        typeDict = {2412: '1',
                    2417: '2',
                    2422: '3',
                    2427: '4',
                    2432: '5',
                    2437: '6',
                    2442: '7',
                    2447: '8',
                    2452: '9',
                    2457: '10',
                    2462: '11',
                    2467: '12',
                    2472: '13',
                    2484: '14'}
        return typeDict.get(val)


    def twoFourRev(self, val):
        """Channel to Frequency converter for 2.4 ghz"""
        typeDict = {1: '2412',
                    2: '2417',
                    3: '2422',
                    4: '2427',
                    5: '2432',
                    6: '2437',
                    7: '2442',
                    8: '2447',
                    9: '2452',
                    10: '2457',
                    11: '2462',
                    12: '2467',
                    13: '2472',
                    14: '2484'}
        return typeDict.get(val)


    def fiveEight(self, val):
        """Frequency to Channel converter for 5.8 GHz"""
        typeDict = {5180: '36',
                    5200: '40',
                    5210: '42',
                    5220: '44',
                    5240: '48',
                    5250: '50',
                    5260: '52',
                    5290: '58',
                    5300: '60',
                    5320: '64',
                    5745: '149',
                    5760: '152',
                    5765: '153',
                    5785: '157',
                    5800: '160',
                    5805: '161',
                    5825: '165'}
        return typeDict.get(val)


    def fiveEightRev(self, val):
        """Channel to Frequency converter for 5.8 GHz"""
        typeDict = {36: '5180',
                    40: '5200',
                    42: '5210',
                    44: '5220',
                    48: '5240',
                    50: '5250',
                    52: '5260',
                    58: '5290',
                    60: '5300',
                    64: '5320',
                    149: '5745',
                    152: '5760',
                    153: '5765',
                    157: '5785',
                    160: '5800',
                    161: '5805',
                    165: '5825'}
