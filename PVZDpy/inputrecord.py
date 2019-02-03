import json
import logging
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.userexceptions import *
__author__ = 'r2h2'


class AodsChangeList:
    ''' Aggregate of different record types to add to the policy journal with a single signature '''
    def __init__(self):
        self.changelist = []

    def append(self, input_rec: InputRecordAllRecordTypes):
        assert isinstance(input_rect, InputRecordAllRecordTypes)
        self.changelist += input_rec

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


''' Classes to create input records for AodsListHandler '''

class InputRecordAbstract:
    pass

class InputRecordIssuer(InputRecordAbstract):
    def __init__(self, subject_cn: str, pvprole: str, cacert: str, delete: bool):
        self.id = f"i/{subject_cn}"
        self.inputrec = {
            "record": [
                "issuer",
                subject_cn,
                pvprole,
                cacert],
            "delete": delete}

    def __str__(self):
        return self.id
    

class InputRecordNamespace(InputRecordAbstract):
    def __init__(self, fqdn: str, gvouid: str, delete: bool):
        self.id = f"n/{fqdn}"
        self.inputrec = {
            "record": [
                "domain",
                fqdn,
                gvouid],
            "delete": delete}

    def __str__(self):
        return self.id


class InputRecordOrganization(InputRecordAbstract):
    def __init__(self, gvouid: str, cn: str, delete: bool):
        self.id = f"n/{gvouid}"
        self.inputrec = {
            "record": [
                "organization",
                gvouid,
                cn],
            "delete": delete}

    def __str__(self):
        return self.id


class InputRecordRevocation(InputRecordAbstract):
    def __init__(self, cert: str, subject_cn: str, delete: bool):
        self.id = f"r/{subject_cn}"
        self.inputrec = {
            "record": [
                "revocation", 
                cert,
                subject_cn],
            "delete": delete}

    def __str__(self):
        return self.id


class InputRecordUserprivilege(InputRecordAbstract):
    def __init__(self, cert: str, gvouid: str, subject_cn: str, delete: bool):
        self.id = f"u/{subject_cn}"
        self.inputrec = {
            "record": [
                "userprivilege",
                cert,
                gvouid,
                subject_cn],
            "delete": delete}

    def __str__(self):
        return self.id
