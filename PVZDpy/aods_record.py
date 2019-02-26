import base64
import datetime
import hashlib
import json
import logging
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.policychange import PolicyChangeItemAbstract


class AodsRecord:
    """ Wraps the ContentRecord with an administrative header (hash, seq, delete flag)
        and trailer (datetimestamp, registrant and submitter)
    """
    def __init__(self, sourcerec):
        if isinstance(sourcerec, PolicyChangeItemAbstract):
            self.create_from_changeitem(sourcerec)
        elif isinstance(sourcerec, list):
            self.create_from_aodsrec(sourcerec)
        else:
            raise Exception('invalid arg type')

    def create_from_changeitem(
            self,
            changeitem: PolicyChangeItemAbstract,
            registrant: str = '',
            submitter: str = '') -> None:
        try:
            self.hash = None
            self.seq = None
            self.deleteflag = changeitem.is_delete()
            self.contentfields = changeitem.get_ContentRecord().fields
            self.datetimestamp = datetime.datetime.isoformat(datetime.datetime.utcnow()) + '+00:00'
            self.registrant = registrant
            self.submitter = submitter
        except Exception as e:
            logging.error(str(self))
            raise e

    def create_from_aodsrec(self, aodsrec: dict):
        ''' load existing aods record from hash chain '''
        try:
            self.hash = aodsrec[0]
            self.seq = aodsrec[1]
            self.deleteflag = aodsrec[2]
            self.contentfields = aodsrec[3]
            self.datetimestamp = aodsrec[4]
            self.registrant = aodsrec[5]
            self.submitter = aodsrec[6]
        except Exception as e:
            logging.error(str(self))
            raise e

    def get_ContentRecord(self) -> list:
        return ContentRecord(self.contentfields)

    def validate_hash(self, prevHash: str) -> bool:
        assert isinstance(prevHash, str)
        aodsrec_val = [
            self.hash,
            self.seq,
            self.deleteflag,
            self.contentfields,
            self.datetimestamp,
            self.registrant,
            self.submitter]
        digestbase = prevHash + json.dumps(aodsrec_val[1:], separators=(',', ':'))
        # logging.debug('digestbase=' + digestbase)
        digest_bytes = base64.b64encode(hashlib.sha256(digestbase.encode('ascii')).digest())
        return (digest_bytes.decode('ascii') == self.hash)

    def get_rec_with_hash(self, newSeq: str, lastHash: str) -> list:
        """ compute hash: take last hash and append the representation of the wrapped structure
        of json.dumps in compact representaion
        :param newSeq: Sequence number to be assigned to the new record
        :param lastHash: hash value of last record in aods
        :return: wrapped structure to be appended to aods including hash
        """
        assert isinstance(lastHash, str)
        logging.debug("%d last_hash: " % newSeq + lastHash)
        aodsrec_list = [
            "placeholder_for_digest",
            newSeq,
            self.deleteflag,
            self.contentfields,
            self.datetimestamp,
            self.registrant,
            self.submitter,
        ]
        aodsrec_json = json.dumps(aodsrec_list[1:], separators=(',', ':'))
        digestbase = lastHash + aodsrec_json
        digestbase_bytes = digestbase.encode('utf-8')
        digest_str = base64.b64encode(hashlib.sha256(digestbase_bytes).digest()).decode('ascii')
        logging.debug('digestbase=' + digestbase + '\n        digest_str=' + digest_str)
        return [digest_str] + aodsrec_list[1:]

    def __str__(self) -> str:
        op = 'del' if self.deleteflag else 'add'
        cf = ', '.join(self.contentfields)
        return str(self.seq or '') + ' ' + str(self.hash or '') + f" {op} {cf}"
