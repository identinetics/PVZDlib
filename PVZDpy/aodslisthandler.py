import base64, hashlib, sys
import logging
import json
from datetime import datetime
from json2html import *
from PVZDpy.inputrecord import InputRecordAllRecordTypes
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.wrapperrecord import WrapperRecord
from PVZDpy.userexceptions import *
from PVZDpy.xy509cert import XY509cert

__author__ = 'r2h2'
assert sys.version_info >= (3,4), 'modules used here support unicode and require python 3.'


class AodsListHandler:
    ''' The append-only data structure is agnostic of the record type, which is defined in as content record. Its
        primitives are create, append and read and scretch.
        The read function will transform it into the policyDict structure.
    '''

    def __init__(self, aodsFileHandler, inv_args):
        self.aodsFileHandler = aodsFileHandler
        self.args = inv_args
        self.lastSeq = None
        self.lastHash = None
        self.prevHash = None


    def aods_append(self):
        try:
            with open(self.args.inputfilename, encoding='utf8') as fd:
                inputdataJSON = fd.read()
        except (OSError, IOError) as e:
            logging.error('could not read inputfile, because: %s' %(repr(e)))
            sys.exit(1)
        try:
            appendList = json.loads(inputdataJSON)
        except Exception as e:
            raise JSONdecodeError
        if not isinstance(appendList, list):
            raise PMPInputRecNoDictError('JSON input file must contain a list of dict')
        if len(appendList) == 0:
            raise PMPInputRecNoDictError('JSON input file must contain a non-empty list of dict')
        if not isinstance(appendList[0], dict):
            raise PMPInputRecNoDictError('JSON input file: first object in list is not a dict')
        self.aods = self.aodsFileHandler.readFile() # does validation as well
        inputRecSeq = 0
        for inputDataRaw in appendList:
            inputRec = InputRecordAllRecordTypes(inputDataRaw)
            wrapperRec = WrapperRecord('elements', inputRec,
                                       registrant = self.args.registrant,
                                       submitter = self.args.submitter)
            inputRecSeq += 1
            policyDict = self.aods_read(use='internal')  # get latest version
            logging.debug("%d rectype=%s pk=%s" % (inputRecSeq, inputRec.rec.rectype, inputRec.rec.primarykey))
            inputRec.validate(policyDict)
            lastHash = self.aods['AODS'][self.lastSeq][0]
            logging.debug("%d lastHash: " % inputRecSeq + lastHash)
            wrapperRec_final = wrapperRec.getRec(self.lastSeq + 1, lastHash)
            self.aods['AODS'].append(wrapperRec_final)
        self.aodsFileHandler.save(self.aods)


    def aods_create(self):
        inputDataRaw = {"record": ["header", "",
                                   "columns: hash, seq, delete, [rectype, pk, a1, a2, ..], "
                                   "datetimestamp, registrant, submitter]" ],
                        "delete": False}
        inputRec = InputRecordAllRecordTypes(inputDataRaw)
        wrapperRec = WrapperRecord('elements', inputRec)
        seedVal_str = str(datetime.now())
        seedVal_bytes = base64.b64encode(hashlib.sha256(seedVal_str.encode('ascii')).digest())
        #if self.args.debug: seedVal_bytes = 'fixedValueForDebugOnly'.encode('ascii')
        logging.debug("0 seedVal: " + seedVal_bytes.decode('ascii'))
        self.aodsFileHandler.create({"AODS": [wrapperRec.getRec(0, seedVal_bytes.decode('ascii'))]})


    def write_entry_into_policy_dict(self, policyDict, new_rec, deleteflag):
        """ Update the policy directory with a journal entry, that may insert a new entry or
            update or delete and existing one. Multiple userprivilege records with the same key
            are accumulated into a single entry with a list of orgids.
        """
        if deleteflag:
            if new_rec.rectype == "userprivilege":
                # attr[0] is a list; delete updates list of orgids if len(orgids) > 1
                try:
                    oldrec_attr = policyDict["userprivilege"][new_rec.primarykey]
                except KeyError:
                    raise InputValueError('Input error: deleting userprivilege record without previous entry for this cert: ' +
                                          new_rec.primarykey + ', orgid: ' + new_rec.attr[0])
                orgids = oldrec_attr[0]
                if new_rec.attr[0] in orgids:
                    orgids.remove(new_rec.attr[0])
                else:
                    raise InputValueError('Input error: deleting userprivilege record without orgid for this cert: ' +
                                          new_rec.primarykey + ', orgid: ' + new_rec.attr[0])
                if len(orgids) > 0:
                    new_rec.attr[0] = orgids
                    policyDict[new_rec.rectype].update({new_rec.primarykey: new_rec.attr})
                else:
                    del policyDict[new_rec.rectype][new_rec.primarykey]
            else:
                try:
                    del policyDict[new_rec.rectype][new_rec.primarykey]
                except KeyError:
                    raise InputValueError('Input error: deleting record without previous entry: ' +
                                          new_rec.rectype + ', ' + new_rec.primarykey)
        else:
            try:
                if new_rec.rectype == "userprivilege":
                    # attr[0] is a list of orgids; if record exists for this certificate then
                    # merge existing orgids with the new one
                    # note: using dict.update() to either insert or overwrite the dict entry
                    try:
                        orgids = policyDict["userprivilege"][new_rec.primarykey][0]
                    except KeyError:
                        orgids = []
                    if new_rec.attr[0] not in orgids:  # insert orgid
                        orgids += [new_rec.attr[0]]
                        new_rec.attr[0] = orgids
                    else: # duplicate orgid, keep previous state
                        new_rec.attr[0] = policyDict["userprivilege"][new_rec.primarykey][0]
                policyDict[new_rec.rectype].update({new_rec.primarykey: new_rec.attr})
            except KeyError as e:
                logging.error(str(wrap) + ' ' + str(new_rec), file=sys.stderr)
                raise e


    def aods_read(self, use='external') -> dict:
        '''   read aods from input file and transform into policyDict structure
              option: output policiy directory or journal in various formats
        '''
        if not hasattr(self, 'aods'):
            self.aods = self.aodsFileHandler.readFile()
        if self.aods['AODS'][0][3][0] != 'header':
            raise ValidationError('Cannot locate aods header record')
        policyDict = {"domain": {}, "issuer": {}, "organization": {}, "revocation": {}, "userprivilege": {}}
        if use == 'external' and getattr(self.args, 'journal', False):
            dump_journal_fd = open(self.args.journal, 'w')
            dump_journal_fd.write('[\n')
        for w in self.aods['AODS']:
            if use == 'external' and getattr(self.args, 'journal', False):
                dump_journal_fd.write(json.dumps(w) + '\n')
            wrap = WrapperRecord('rawStruct', w)
            rec = ContentRecord(wrap.record)
            self.prevHash = self.lastHash
            self.lastHash = wrap.hash
            self.lastSeq = wrap.seq
            if rec.rectype == 'header':
                continue
            if wrap.validateWrap(self.prevHash) != True:
                raise HashChainError('AODS hash chain is broken -> data not trustworthy, revert to previous version')
            self.write_entry_into_policy_dict(policyDict, rec, wrap.deleteflag)
        if use == 'external':   # avoid dumps for each append iteration
            if use == 'external' and getattr(self.args, 'journal', False):
                dump_journal_fd.write(']\n')
                dump_journal_fd.close()
            self.dump_poldir(policyDict)
        return policyDict


    def dump_poldir(self, policyDict):
        if getattr(self.args, 'poldirhtml', False):
            html = '<html><head><meta charset="UTF-8"><link rel="stylesheet" type="text/css" ' \
                   'href="../tables.css"></head><body><h1>PVZD Policy Directory</h1>%s</body></html>'
            tabhtml = json2html.convert(json=policyDict, table_attributes='class="pure-table"')
            self.args.poldirhtml.write(html % tabhtml)
            self.args.poldirhtml.close()
        if getattr(self.args, 'poldirjson', False):
            self.args.poldirjson.write(json.dumps(policyDict, sort_keys=True, indent=2, separators=(', ', ': ')))
            self.args.poldirjson.close()
        if getattr(self.args, 'shibacl', False):
            self._write_shib_requestmapper_acl(policyDict)
        if getattr(self.args, 'printtrustedcerts', False):
            self._write_trustedcerts(policyDict)


    def _write_shib_requestmapper_acl(self, policyDict):
        '''  List of user certificates from policy dict AND trusted certificates
             The output file is to be included in a shibboleth2.xml <RequestMapper> element
        '''
        self.args.shibacl.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        self.args.shibacl.write('<AccessControl type="edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl">\n')
        self.args.shibacl.write('  <Rule require="EID-SIGNER-CERTIFICATE">\n')
        prefix='{cert}'
        for cert in sorted(policyDict['userprivilege']):
            if cert.startswith(prefix):
                self.args.shibacl.write('    ' + cert[len(prefix):] + '\n')
            else:
                print('invalid format of userprivilege in policy directory', file=sys.stderr)

        for cert in self.aodsFileHandler.trustedCerts:
            self.args.shibacl.write('    ' + cert + '\n')
        self.args.shibacl.write('  </Rule>\n</AccessControl>')
        self.args.shibacl.close()


    def _write_trustedcerts(self, policyDict):
        '''  Print trusted certificates
        '''
        for cert_pem in self.aodsFileHandler.trustedCerts:
            cert = XY509cert(cert_pem, inform='PEM')  # TODO: check encoding
            self.args.printtrustedcerts.write('Subject: ' + cert.getSubject_str() + '; ')
            self.args.printtrustedcerts.write('issuer: ' + cert.getIssuer_str() + '; ')
            self.args.printtrustedcerts.write('not valid after: ' + cert.notAfter_str() + '\n')
        self.args.printtrustedcerts.close()


    def aods_scratch(self):
        self.aodsFileHandler.removeFile()
