import json
import lxml.etree
from os.path import join as opj
import os
import pytest
import tempfile
from PVZDpy.constants import *
from PVZDpy.userexceptions import *
from PVZDpy.samled_validator import SamlEdValidator

#path_prefix = 'PVZDpy/tests/testdata/saml/'
path_prefix_testin = 'testdata/saml/'
path_prefix_testout = 'testout/samled_validator'
#@pytest.fixture
#def domains7():
#    return ['*.identinetics.com']

#@pytest.fixture
#def orgids7():
#    return ['AT:VKZ:XFN-318886a']

#@pytest.fixture
#def signerCert7():
#    with open(path_prefix_testin+'signercert7_rh.pem') as fd:
#        return fd.read()

@pytest.fixture
def poldir1():
    with open(path_prefix_testin+'poldir1.json') as fd:
        d = json.load(fd)
    return d

@pytest.fixture
def ed_path(file_index: int):
    path = (
        'idpExampleCom_idpXml.xml',
        '01_idp_valid_cert.xml',
        '02_idp_valid_xml_invalid_cert.xml',
        '03_idp_valid_unsigned_c14n.xml',
        '04_idp_delete.xml',
        '05_idp_cert_untrusted_root.xml',
        '06_idp_valid_expired_cert.xml',
        '07_idp_identinetics.xml',
        '08_idp_invalidXml.xml',
        '09_idp_invalidXsd.xml',
        '10_idp_signed.xml',
        '11_idp_unauthz_signator.xml',
        '12_idp_entitiesdescriptor.xml',
        '13_idp_entitiesdescriptor_2idps.xml',
        '14_01_plus_reginfo.xml',
        '15_10_signature_removed.xml',
        '16_cert_subject_mismatch_gondorWienGvAt_idp.xml',
        '17_endpoint_mismatch_idp1IdentineticsCom_idpXml.xml',
    )
    return path[file_index]

def ed_path_testin(file_index: int):
    return opj(path_prefix_testin, ed_path(file_index))

def ed_path_testout(file_index: int, test_index: int):
    os.makedirs(path_prefix_testout, exist_ok=True)
    return opj(path_prefix_testout, 'test{}_ed{}.json'.format(str(file_index), str(test_index)))

def ed_path_test_expected(file_index: int, test_index: int):
    return opj(path_prefix_testin, 'samled_val_expected_results',
               'test{}_ed{}.json'.format(str(file_index), str(test_index)))

#@pytest.fixture
#def ed(file_index: int):

def run_test_with_edpath(file_index: int):
    ed = SamlEdValidator(poldir1())
    ed.validate_entitydescriptor(ed_path_new=ed_path_testin(file_index))
    ed_dict = ed.get_obj_as_dict()
    with open(ed_path_testout(1, file_index), 'w') as fd:
        fd.write(json.dumps(ed_dict))

def test01_edval_edpath():
    for file_index in range(1, 18):
        run_test_with_edpath(file_index)

def run_test_with_xmlstr(file_index: int):
    ed = SamlEdValidator(poldir1())
    with open(ed_path_testin(file_index)) as fd:
        ed.validate_entitydescriptor(ed_str_new=fd.read())
    ed_dict = ed.get_obj_as_dict()
    fn1_testout = ed_path_testout(2, file_index)
    fn2_testexp = ed_path_test_expected(2, file_index)
    with open(fn1_testout, 'w') as fd1:
        fd1.write(json.dumps(ed_dict, indent=2, sort_keys=True))
    with open(fn1_testout) as fd1:
        with open(fn2_testexp) as fd2:
            assert fd1.read() == fd2.read()
    os.unlink(fn1_testout)

def test02_edval_str():
    for file_index in range(1, 18):
        run_test_with_xmlstr(file_index)
