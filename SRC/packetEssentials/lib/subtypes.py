class Subtypes(object):
    """This class is for naming of subtypes where symStrings doesn't work"""

    def mgmtSubtype(self, val):
            """Management Frame Subtypes"""
            subDict = {0: 'Association Req.',
                       1: 'Association Resp.',
                       2: 'Reassociation Req.',
                       3: 'Reassociation Resp.',
                       4: 'Probe request',
                       5: 'Probe response',
                       8: 'Beacon',
                       9: 'AITM',
                       10: 'Disassociation',
                       11: 'Authentication',
                       12: 'Deauthentication',
                       13: 'Action',
                       14: 'Action no ACK'}
            return subDict.get(val)


    def ctrlSubtype(self, val):
        """Control Frame Subtypes"""
        subDict = {0: 'Reserved',
                   1: 'Reserved',
                   2: 'Reserved',
                   3: 'Reserved',
                   4: 'Reserved',
                   5: 'Reserved',
                   6: 'Reserved',
                   7: 'Control wrapper',
                   8: 'Block Ack Req',
                   9: 'Block Ack',
                   10: 'PS-Poll',
                   11: 'RTS',
                   12: 'CTS',
                   13: 'ACK',
                   14: 'CF-End',
                   15: 'CF-End and CF-ACK'}
        return subDict.get(val)


    def dataSubtype(self, val):
        """Data Frame Subtypes"""
        subDict = {0: 'Data',
                   1: 'Data + CF-ACK [PCF Only]',
                   2: 'Data + CF-Poll [PCF Only]',
                   3: 'Data + CF-ACL + CF-Poll [PCF Only]',
                   4: 'Null (no data)',
                   5: 'CF-ACK (no data) [PCF Only]',
                   6: 'CF-Poll (no data) [PCF Only]',
                   7: 'CF-ACK + CF-Poll (no data) [PCF Only]',
                   8: 'QoS Data [HCF]',
                   9: 'QoS Data + CF-ACK [HCF]',
                   10: 'QoS Data + CF-Poll [HCF]',
                   11: 'QoS Data + CF-ACK + CF-Poll [HCF]',
                   12: 'QoS Null (no data) [HCF]',
                   13: 'Reserved',
                   14: 'QoS CF-Poll (no data) [HCF]',
                   15: 'QoS CF-ACK + CF-Poll (no data) [HCF]'}
