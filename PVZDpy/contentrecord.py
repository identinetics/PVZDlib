from __future__ import print_function
from PVZDpy.userexceptions import InputFormatError, InputValueError
from PVZDpy.constants import RECORDTYPES


''' Encapsulate the structure of record types (TODO: convert to base class + extensions) '''


class ContentRecord:
    ''' Handle a single content record, which is a list of following fields:
            record type
            primary key
            one or more attributes
    '''
    def __init__(self, fields: list):
        if len(fields) < 3:
            raise InputValueError('ContentRecord must be created with a field list at least 3 elements long')
        if fields[0] not in RECORDTYPES:
            raise InputValueError('invalid record type: %s' % self.rectype)
        self.fields = fields
        self.rectype = fields[0]
        self.primarykey = fields[1]
        self.attr = fields[2:]

    def validate(self, dir: dict, deleteflag: bool):
        self._validate_primarykey(dir, deleteflag)
        self._validate_issuer(dir)
        self._validate_namespaceobj(dir)
        self._validate_organization(dir)
        self._validate_revocation(dir)
        self._validate_userprivilege(dir)

    def _validate_primarykey(self, dir: dict, deleteflag: bool):
        if not isinstance(self.primarykey, str):
            raise InputFormatError('primary key of record must be of type string')
        if self.primarykey == '':
            raise InputValueError('primary key of record must not be empty')
        if deleteflag and self.primarykey not in dir[self.rectype]:
            raise InputValueError('delete command for non-existing record, rec=' + ', '.join(self.fields))

    def _validate_issuer(self, dir: dict):
        if self.rectype == "issuer":
            if len(self.attr) != 2:
                raise InputFormatError('issuer record must have exactly 2 attributes '
                                       '("pvprole" and "certificate (PEM)")')
            if not isinstance(self.attr[0], str):
                raise InputFormatError('pvprole must be of type string')
            if not (self.attr[0] in ('IDP', 'SP')):
                raise InputFormatError("pvprole must be 'IDP' or 'SP")
            if not isinstance(self.attr[1], str):
                raise InputFormatError('Certificate (2nd attribute of issuer record) must be of type string')

    def _validate_namespaceobj(self, dir: dict):
        if self.rectype == "domain":
            if len(self.attr) != 1:
                raise InputFormatError('domain record must have exactly 1 attribute (the org-id)')
            if not isinstance(self.attr[0], str):
                raise InputFormatError('org-id (first attribute of domain record) must be of type string')
            if self.attr[0] not in dir['organization']:
                raise InputValueError(
                    'adding domain record referencing non-existing organization, orgid = %s' % self.attr[0])

    def _validate_organization(self, dir: dict):
        if self.rectype == "organization":
            if len(self.attr) != 1:
                raise InputFormatError('organization record must have exactly 1 attribute (the org-id)')
            if not isinstance(self.attr[0], str):
                raise InputFormatError('org-name (first attribute of organization record) must be of type string')

    def _validate_revocation(self, dir: dict):
        if self.rectype == "revocation":
            if len(self.attr) != 1:
                raise InputFormatError('revocation record must have exactly 1 attribute (the "reason text")')
            if not isinstance(self.attr[0], str):
                raise InputFormatError('reason (1st attribute of revocation record) must be of type string')

    def _validate_userprivilege(self, dir: dict):
        if self.rectype == "userprivilege":
            if self.primarykey[0:6] != '{cert}':  # bPK ('{ssid}') not implemented
                raise InputFormatError('primary key of userprivilege must start with {cert}')
            if len(self.attr) != 2:
                raise InputFormatError('user privilege record must have 2 attributes (org-id, name')
            if not isinstance(self.attr[0], str):
                raise InputFormatError('org-id (first attribute of user privilege record) must be of type string')
            if not isinstance(self.attr[1], str):
                raise InputFormatError('cert (2nd attribute of user privilege record) must be of type string')
            if self.attr[0] not in dir['organization']:
                raise InputValueError('adding user privilege record referencing non-existing '
                                      'organization, pk=%s, orgid=%s' % (self.primarykey[:20], self.attr[0]))

    def __str__(self):
        return self.rectype + ' ' + self.primarykey
