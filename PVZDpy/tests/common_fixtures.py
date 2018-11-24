import json
import pytest

path_prefix_testin = 'testdata/saml/'
path_prefix_testout = 'testout/samled_validator'


@pytest.fixture
def poldir1():
    with open(path_prefix_testin+'poldir1.json') as fd:
        d = json.load(fd)
    return d


@pytest.fixture
def ed_path(file_index: int):
    path = (
        'unsigned_ed/idpExampleCom_idpXml.xml',
        'unsigned_ed/01_idp_valid_cert.xml',
        'unsigned_ed/02_idp_valid_xml_invalid_cert.xml',
        'unsigned_ed/03_idp_valid_c14n.xml',
        'unsigned_ed/04_idp_delete.xml',
        'unsigned_ed/05_idp_cert_untrusted_root.xml',
        'unsigned_ed/06_idp_entitiesdescriptor.xml',
        'unsigned_ed/07_idp_identinetics.xml',
        'unsigned_ed/08_idp_invalidXml.xml',
        'unsigned_ed/09_idp_invalidXsd.xml',
        'signed_ed/10_idp_signed.xml',
        'signed_ed/11_idp_unauthz_signator.xml',
        'signed_ed/12_idp_valid_expired_cert_sig.xml',
        'signed_ed/13_idp_entitiesdescriptor_2idps.xml',
        'signed_ed/14_cert_subject_mismatch_gondorWienGvAt_idp.xml',
        'signed_ed/15_endpoint_mismatch_idp1IdentineticsCom_idpXml.xml',
        'samled_expected_results/16_01_plus_reginfo.xml',
        'samled_expected_results/17_idp_signed_10_edit.xml',
        'signed_ed/18_idpIdentineticsCom_idpXml.xml',
        'samled_expected_results/19_ed_from_cert.xml',
        'samled_expected_results/20_ed_from_cert.xml',
    )
    return path_prefix_testin + path[file_index]


@pytest.fixture
def cert1():
    with open(path_prefix_testin+'cert1_redmineIdentineticsCom-cer.pem') as fd:
        return fd.read()

