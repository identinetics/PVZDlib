import json
import logging
from pathlib import Path
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.userexceptions import *

''' Classes to create input records for the policy journal'''

class PolicyChangeItemAbstract:
    ''' A change item is a content record plus an operation
            delete=False: add/modify
            delete=True: delete
    '''
    def __init__(self):
        self.id_str = 'abstract'
        self.inputrec = {
            "content": [
                "abstract",
                'pk',
                'attr1'],
            "delete": False}

    def get_ContentRecord(self):
        return ContentRecord(self.inputrec['content'])

    def is_delete(self):
        return self.inputrec['delete']

    # TODO: refactor this to direct call to ContentRecord
    def validate(self, dir):
        try:
            self.contentrec.validateRec(dir, self.deleteflag)
        except (InputValueError, InputFormatError) as e:
            raise e

    def __str__(self):
        return self.id_str


class PolicyChangeGeneric(PolicyChangeItemAbstract):
    def __init__(self, inputrec):
        self.id_str = f"generic"
        self.inputrec = inputrec


class PolicyChangeHeader(PolicyChangeItemAbstract):
    def __init__(self):
        self.id_str = f"header"
        self.inputrec = {
            "content":
               ["header",
                "",
                "columns: hash, seq, delete, [rectype, pk, attr1, ..], datetimestamp, registrant, submitter]"
               ],
            "delete": False}


class PolicyChangeIssuer(PolicyChangeItemAbstract):
    def __init__(self, subject_cn: str, pvprole: str, cacert: str, delete: bool):
        self.id_str = f"i/{subject_cn}"
        self.inputrec = {
            "content": [
                "issuer",
                subject_cn,
                pvprole,
                cacert],
            "delete": delete}


class PolicyChangeNamespace(PolicyChangeItemAbstract):
    def __init__(self, fqdn: str, gvouid: str, delete: bool):
        self.id_str = f"n/{fqdn}"
        self.inputrec = {
            "content": [
                "domain",
                fqdn,
                gvouid],
            "delete": delete}


class PolicyChangeOrganization(PolicyChangeItemAbstract):
    def __init__(self, gvouid: str, cn: str, delete: bool):
        self.id_str = f"n/{gvouid}"
        self.inputrec = {
            "content": [
                "organization",
                gvouid,
                cn],
            "delete": delete}


class PolicyChangeRevocation(PolicyChangeItemAbstract):
    def __init__(self, cert: str, subject_cn: str, delete: bool):
        self.id_str = f"r/{subject_cn}"
        self.inputrec = {
            "content": [
                "revocation", 
                cert,
                subject_cn],
            "delete": delete}


class PolicyChangeUserprivilege(PolicyChangeItemAbstract):
    def __init__(self, cert: str, gvouid: str, subject_cn: str, delete: bool):
        self.id_str = f"u/{subject_cn}"
        self.inputrec = {
            "content": [
                "userprivilege",
                cert,
                gvouid,
                subject_cn],
            "delete": delete}


''' Policy changes: define input for Policy Journal '''

class PolicyChangeList:
    ''' Aggregate of different record types to add to the policy journal with a single signature '''
    def __init__(self):
        self.changelist = []   # list of PolicyChangeItemAbstract derived instances

    def __len__(self):
        return len(self.changelist)

    def append(self, changeitem: PolicyChangeItemAbstract):
        assert isinstance(changeitem, PolicyChangeItemAbstract)
        self.changelist += changeitem

    def load(self, testdata_json: Path):
        changelist_of_dict = json.load(testdata_json.open())
        for changeitem_dict in changelist_of_dict:
            changeitem_generic = PolicyChangeGeneric(changeitem_dict)
            self.changelist.append(changeitem_generic)
