import json
import logging
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.userexceptions import *
__author__ = 'r2h2'


class InputRecordAllRecordTypes:
    ''' Handle a record of any type to be appended '''

    def __init__(self, appendData):
        if not isinstance(appendData, dict):
            raise PMPInputRecNoDictError('input record to be appended must be of type dict')
        if 'record' not in appendData:
            raise ValidationError('input record dict must have the key "record"')
        self.rec = ContentRecord(appendData['record'])
        self.deleteflag = appendData['delete']
        if not isinstance(self.deleteflag, bool):
            raise ValidationError('deleteflag must be of type boolean')

    def validate(self, dir):
        try:
            self.rec.validateRec(dir, self.deleteflag)
        except (InputValueError, InputFormatError) as e:
            raise e


class InputRecordAbstract:
    def as_json(self):
        return json.dumps(self.inputrec)


class InputRecordIssuer(InputRecordAbstract):
    def __init__(self, cacert: str, pvprole: str, subject_cn: str, delete: bool):
        self.inputrec = {
            "record": [
                "issuer", 
                subject_cn, 
                pvprole,
                cert],
            "delete": delete}
    

class InputRecordNamespace(InputRecordAbstract):
    def __init__(self, fqdn: str, gvouid: str, delete: bool):
        self.inputrec = {
            "record": [
                "domain", 
                fqdn,
                gvouid],
            "delete": delete}


class InputRecordRevocation(InputRecordAbstract):
    def __init__(self, cert: str, subject_cn: str, delete: bool):
        self.inputrec = {
            "record": [
                "revocation", 
                cert,
                subject_cn],
            "delete": delete}


class InputRecordUserprivilege(InputRecordAbstract):
    def __init__(self, cert: str, pvprole: str, subject_cn: str, delete: bool):
        self.inputrec = {
            "record": [
                "issuer",
                cert,
                gvouid,
                subject_cn],
            "delete": delete}
