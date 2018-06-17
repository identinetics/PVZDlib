from __future__ import print_function
import base64, hashlib, datetime, sys
import logging
import json
#from inputRecord import InputRecord
__author__ = 'r2h2'

#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

""" Classes in this source file encapsulate the structure of record types """

class WrapperRecord:
    """ Create an object from either input record or an aods record.
        A wrapper record is the list header that provides administrative data such as the hash,
        sequence number and delete flag around content records, followed by the datetimestamp,
        registrant and submitter.
    """
    def __init__(self, argtype, *args):
        if argtype == 'elements':
            """ create record from input data """
            try:
                self.hash = None
                self.seq = None
                self.deleteflag = args[0].deleteflag
                self.rec = args[0].rec
                self.datetimestamp = datetime.datetime.isoformat(datetime.datetime.utcnow()) + '+00:00'
                self.args = args[1]
                self.registrant = self.args.registrant
                self.submitter = self.args.submitter
            except Exception as e:
                logger.error(str(self))
                raise e
        elif argtype == 'rawStruct':
            rawStruct = args[0]
            self.args = args[1]
            """ rawStruct: wrapper record read from aods file """
            try:
                self.hash = rawStruct[0]
                self.seq = rawStruct[1]
                self.deleteflag = rawStruct[2]
                self.record = rawStruct[3]
                self.datetimestamp = rawStruct[4]
                self.registrant = rawStruct[5]
                self.submitter = rawStruct[6]
            except Exception as e:
                logger.error(str(self))
                raise e
        else: raise Exception

    def validateWrap(self, prevHash):
        """ validate hash chain
        :param prevHash: hash value of previous record in aods
        :return: True if valid
        """
        assert isinstance(prevHash, str)
        wrapRec = [self.hash, self.seq, self.deleteflag, self.record,
                   self.datetimestamp, self.registrant, self.submitter]
        digestBase = prevHash + json.dumps(wrapRec[1:], separators=(',', ':'))
        # logging.debug('digestBase=' + digestBase)
        digest_bytes = base64.b64encode(hashlib.sha256(digestBase.encode('ascii')).digest())
        return (digest_bytes.decode('ascii') == self.hash)

    def getRec(self, newSeq, lastHash) -> list:
        """ compute hash: take last hash and append the representation of the wrapped structure
        of json.dumps in compact representaion
        :param newSeq: Sequence number to be assigned to the new record
        :param lastHash: hash value of last record in aods
        :return: wrapped structure to be appended to aods including hash
        """
        assert isinstance(lastHash, str)
        logging.debug("%d lastHash: " % newSeq + lastHash)
        wrapList = ["placeholder_for_digest", newSeq, self.deleteflag, self.rec.raw,
                    self.datetimestamp, self.registrant, self.submitter]
        wrapStructJson = json.dumps(wrapList[1:], separators=(',', ':'))
        digestBase = lastHash + wrapStructJson
        digestBase_bytes = digestBase.encode('utf-8')
        digest_str = base64.b64encode(hashlib.sha256(digestBase_bytes).digest()).decode('ascii')
        logging.debug('digestBase=' + digestBase + '\n        digest_str=' + digest_str)
        return [digest_str] + wrapList[1:]

    def __str__(self):
        return str(self.seq) + ' ' + self.hash
