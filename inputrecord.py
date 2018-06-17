import logging
from contentrecord import ContentRecord
from userexceptions import *
__author__ = 'r2h2'


class InputRecord:
    ''' Handle a record to be appended '''

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

