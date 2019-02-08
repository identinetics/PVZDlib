import base64
import hashlib
import json
import logging
import sys
from datetime import datetime
from json2html import *
from PVZDpy.aods_record import AodsRecord
from PVZDpy.aodsfilehandler import AodsFileHandler
#from PVZDpy.config.appconfig_abstract import PVZDlibConfigAbstract
from PVZDpy.contentrecord import ContentRecord
from PVZDpy.policychange import PolicyChangeList, PolicyChangeHeader
from PVZDpy.trustedcerts import TrustedCerts
from PVZDpy.userexceptions import HashChainError, InputValueError, PolicyChangeListEmpty
from PVZDpy.userexceptions import PolicyJournalNotInitialized, ValidationError
from PVZDpy.xy509cert import XY509cert

assert sys.version_info >= (3, 6)


class AodsListHandler:
    ''' The append-only data structure is agnostic of the record type, which is defined in as content record. Its
        primitives are append (implies create if empty), read and remove.
        The read function will return the policy dictionary.
    '''
    def __init__(self):
        self.aods = None  # a.k.a. policy journal
        self.aodsfh = AodsFileHandler()
        #self.pvzdconf = PVZDlibConfigAbstract.get_config()
        self.trusted_certs = TrustedCerts().certs
        self.last_seq = None
        self.last_hash = None
        self.prev_hash = None

    def append(self, policy_change_list: PolicyChangeList):
        def validate_contentrec():
            contentrec = changeitem.get_ContentRecord()
            logging.debug("%d rectype=%s pk=%s" % (logging_counter, contentrec.rectype, contentrec.primarykey))
            contentrec.validate(policydict, changeitem.is_delete())

        if len(policy_change_list) == 0:
            raise PolicyChangeListEmpty('policy change list is empty')
        try:
            self._read_or_init_aods()
        except Exception as e:
            print(str(e))
        logging_counter = 0
        for changeitem in policy_change_list.changelist:
            logging_counter += 1
            policydict = self.read()  # refresh because foreign keys may reference previously added primary keys
            validate_contentrec()
            aodsrec = AodsRecord(changeitem)
            lastHash = self.aods['AODS'][self.last_seq][0]
            logging.debug("%d last_hash: " % logging_counter + lastHash)
            wrapper_rec_final = aodsrec.get_rec_with_hash(self.last_seq + 1, lastHash)
            self.aods['AODS'].append(wrapper_rec_final)
        self.save()

    def read(self) -> dict:
        ''' load policy dictionary from policy journal '''
        if not self.aods:
            self._read_or_init_aods()
        policyDict = {"domain": {}, "issuer": {}, "organization": {}, "revocation": {}, "userprivilege": {}}
        for aodsrec_fieldlist in self.aods['AODS']:
            aodsrec = AodsRecord(aodsrec_fieldlist)
            contentrec = aodsrec.get_ContentRecord()
            self.prev_hash = self.last_hash
            self.last_hash = aodsrec.hash
            self.last_seq = aodsrec.seq
            if contentrec.rectype == 'header':
                continue
            if not aodsrec.validate_hash(self.prev_hash):
                raise HashChainError('AODS hash chain is broken -> data not trustworthy, revert to last good version')
            if aodsrec.deleteflag:
                self._policy_dict_delete(policyDict, contentrec)
            else:
                self._policy_dict_add(policyDict, contentrec)
        return policyDict

    def _read_or_init_aods(self):
        try:
            self.aods = self.aodsfh.read()
        except PolicyJournalNotInitialized:
            self.aods = self._initialize()
        except Exception as e:
            print(str(e))
        self.validate_aods_format()

    def _initialize(self):
        changeitem = PolicyChangeHeader()
        aodsrec = AodsRecord(changeitem)
        seed_str = str(datetime.now())
        seed_bytes = base64.b64encode(hashlib.sha256(seed_str.encode('ascii')).digest())
        # if self.pvzdconf.debug: seed_bytes = 'fixedValueForDebugOnly'.encode('ascii')
        logging.debug("0 seedVal: " + seed_bytes.decode('ascii'))
        logging.warning('Policy Journal was empty - created initial record')
        return {"AODS": [aodsrec.get_rec_with_hash(0, seed_bytes.decode('ascii'))]}

    def _policy_dict_delete(self, policyDict, new_rec: ContentRecord):
        ''' Delete an entry from the policy directory
            Multiple userprivilege records with the same key are accumulated into a single entry with a list of orgids.
        '''
        if new_rec.rectype == "userprivilege":
            # attr[0] is a list; delete updates list of orgids if len(orgids) > 1
            try:
                oldrec_attr = policyDict["userprivilege"][new_rec.primarykey]
            except KeyError:
                raise InputValueError(
                    'Input error: deleting userprivilege record without previous entry for this cert: ' +
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

    def _policy_dict_add(self, policyDict, new_rec: ContentRecord):
        ''' Add an entry to the policy directory
            Multiple userprivilege records with the same key are accumulated into a single entry with a list of orgids.
        '''
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
                else:   # duplicate orgid, keep previous state
                    new_rec.attr[0] = policyDict["userprivilege"][new_rec.primarykey][0]
            policyDict[new_rec.rectype].update({new_rec.primarykey: new_rec.attr})
        except KeyError as e:
            logging.error("Add to policy dict {str(new_rec)}\n{str(e)}", file=sys.stderr)
            raise e

    def remove(self):
        self.aodsfh.remove()

    def save(self):
        self.aodsfh.save_journal(self.aods)
        polcydict = self.read()
        self.aodsfh.save_policydict_json(json.dumps(polcydict))
        self._save_policydict_html(polcydict)
        self._save_shibacl(polcydict)
        self._save_trustedcerts_report()

    def _save_policydict_html(self, policydict):
        html = '<html><head><meta charset="UTF-8"><link rel="stylesheet" type="text/css" ' \
               'href="../tables.css"></head><body><h1>PVZD Policy Directory</h1>%s</body></html>'
        tabhtml = json2html.convert(json=policydict, table_attributes='class="pure-table"')
        self.aodsfh.save_policydict_html(html % tabhtml)

    def _save_shibacl(self, polcydict):
        '''  List of user certificates from policy dict AND trusted certificates
             The output file is to be included in a shibboleth2.xml <RequestMapper> element
        '''
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<AccessControl type="edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl">\n'
               '  <Rule require="EID-SIGNER-CERTIFICATE">\n')
        prefix = '{cert}'
        for cert in sorted(polcydict['userprivilege']):
            if cert.startswith(prefix):
                xml += f"    {cert[len(prefix):]}\n"
            else:
                print('invalid format of userprivilege in policy directory', file=sys.stderr)
        for cert in self.trusted_certs:
            xml += f"    {cert}\n"
        xml += '  </Rule>\n</AccessControl>'
        self.aodsfh.save_shibacl(xml.encode('UTF-8'))

    def _save_trustedcerts_report(self):
        '''  Print human readable copy of trusted certificates, non-authoritative  '''
        pass
        for cert_pem in self.trusted_certs:
            cert = XY509cert(cert_pem, inform='PEM')  # TODO: check encoding
            cert_report = (f"Subject: {cert.getSubject_str()}; "
                           f"issuer: {cert.getIssuer_str()}; "
                           f"not valid after: {cert.notAfter_str()}\n")
        self.aodsfh.save_trustedcerts_report(cert_report)

    def validate_aods_format(self):
        if self.aods['AODS'][0][3][0] != 'header':
            raise ValidationError('Cannot locate aods header record')
