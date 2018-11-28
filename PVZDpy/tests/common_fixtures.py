import json
import os.path
import pytest
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP

path_prefix_testin = 'testdata/saml/'
path_prefix_testout = 'testout/samled_validator'


@pytest.fixture
def poldir1():
    with open(path_prefix_testin+'poldir1.json') as fd:
        d = json.load(fd)
    return d


def ed_path(file_index: int, dir=None):
    path = (
        'unsigned_ed/idpExampleCom_idpXml.xml',
        'unsigned_ed/01_idp1_valid_cert.xml',
        'unsigned_ed/02_idp2_valid_xml_invalid_cert.xml',
        'unsigned_ed/03_idp3_valid_c14n.xml',
        'unsigned_ed/04_idp4_delete.xml',
        'unsigned_ed/05_idp5_cert_self_signed.xml',
        'unsigned_ed/06_idp6_entitiesdescriptor.xml',
        'unsigned_ed/07_idp7_identinetics.xml',
        'unsigned_ed/08_idp8_invalidXml.xml',
        'unsigned_ed/09_idp9_invalidXsd.xml',
        'signed_ed/10_idp10_expired_cert.xml',
        'signed_ed/11_idp_unauthz_signator.xml',
        'signed_ed/12_idp12_valid_expired_cert_sig.xml',
        'signed_ed/13_idp_entitiesdescriptor_2idps.xml',
        'signed_ed/14_cert_subject_mismatch_gondorWienGvAt_idp.xml',
        'signed_ed/15_idp15_endpoint_mismatch.xml',
        'samled_expected_results/16_01_plus_reginfo.xml',
        'samled_expected_results/17_idp_signed_10_edit.xml',
        'signed_ed/18_idpIdentineticsCom_idpXml.xml',
        'samled_expected_results/19_ed_from_cert.xml',
        'samled_expected_results/20_ed_from_cert.xml',
        'signed_ed/21_idp_urn_entityid.xml',
    )
    if dir:
        return os.path.join(dir,path[file_index])
    else:
        return os.path.join(path_prefix_testin + path[file_index])


@pytest.fixture
def cert1():
    with open(path_prefix_testin+'cert1_redmineIdentineticsCom-cer.pem') as fd:
        return fd.read()

@pytest.fixture
def ed0():
    return SAMLEntityDescriptorPVP(ed_path(0), poldir1())

@pytest.fixture
def ed1():
    return SAMLEntityDescriptorPVP(ed_path(1), poldir1())

@pytest.fixture
def ed2():
    return SAMLEntityDescriptorPVP(ed_path(2), poldir1())

@pytest.fixture
def ed3():
    return SAMLEntityDescriptorPVP(ed_path(3), poldir1())

@pytest.fixture
def ed4():
    return SAMLEntityDescriptorPVP(ed_path(4), poldir1())

@pytest.fixture
def ed5():
    return SAMLEntityDescriptorPVP(ed_path(5), poldir1())

@pytest.fixture
def ed6():
    return SAMLEntityDescriptorPVP(ed_path(6), poldir1())

@pytest.fixture
def ed7():
    return SAMLEntityDescriptorPVP(ed_path(7), poldir1())

# cannot use ed8 as fixture - instantiation raises (expected) exception

@pytest.fixture
def ed9():
    return SAMLEntityDescriptorPVP(ed_path(9), poldir1())

@pytest.fixture
def ed10():
    return SAMLEntityDescriptorPVP(ed_path(10), poldir1())

@pytest.fixture
def ed11():
    return SAMLEntityDescriptorPVP(ed_path(11), poldir1())

@pytest.fixture
def ed12():
    return SAMLEntityDescriptorPVP(ed_path(12), poldir1())

# cannot use ed13 as fixture - instantiation raises (expected) exception

@pytest.fixture
def ed14():
    return SAMLEntityDescriptorPVP(ed_path(14), poldir1())

@pytest.fixture
def ed15():
    return SAMLEntityDescriptorPVP(ed_path(15), poldir1())
