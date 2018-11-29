import json
from os.path import join as opj 
import pytest
from ..policystore import PolicyStore
from ..samled_pvp import SAMLEntityDescriptorPVP

path_prefix_testin = opj('testdata', 'saml')
path_prefix_testout = opj('testout', 'samled_validator')


@pytest.fixture
def poldir1():
    with open(opj(path_prefix_testin, 'poldir1.json')) as fd:
        d = json.load(fd)
    return d


@pytest.fixture
def policydict1(poldir1):
    return PolicyStore(policydir=poldir1)


def ed_path(file_index: int, dir=None):
    path = (
        opj('unsigned_ed', 'idpExampleCom_idpXml.xml'),
        opj('unsigned_ed', '01_idp1_valid_cert.xml'),
        opj('unsigned_ed', '02_idp2_valid_xml_invalid_cert.xml'),
        opj('unsigned_ed', '03_idp3_valid_c14n.xml'),
        opj('unsigned_ed', '04_idp4_delete.xml'),
        opj('unsigned_ed', '05_idp5_cert_self_signed.xml'),
        opj('unsigned_ed', '06_idp6_entitiesdescriptor.xml'),
        opj('unsigned_ed', '07_idp7_identinetics.xml'),
        opj('unsigned_ed', '08_idp8_invalidXml.xml'),
        opj('unsigned_ed', '09_idp9_invalidXsd.xml'),
        opj('signed_ed', '10_idp10_expired_cert.xml'),
        opj('signed_ed', '11_idp_unauthz_signator.xml'),
        opj('signed_ed', '12_idp12_valid_expired_cert_sig.xml'),
        opj('signed_ed', '13_idp_entitiesdescriptor_2idps.xml'),
        opj('signed_ed', '14_cert_subject_mismatch_gondorWienGvAt_idp.xml'),
        opj('signed_ed', '15_idp15_endpoint_mismatch.xml'),
        opj('samled_expected_results', '16_01_plus_reginfo.xml'),
        opj('samled_expected_results', '17_idp_signed_10_edit.xml'),
        opj('signed_ed', '18_idpIdentineticsCom_idpXml.xml'),
        opj('samled_expected_results', '19_ed_from_cert.xml'),
        opj('samled_expected_results', '20_ed_from_cert.xml'),
        opj('signed_ed', '21_idp_urn_entityid.xml'),
    )
    if dir:
        return opj(dir, path[file_index])
    else:
        return opj(path_prefix_testin, path[file_index])


@pytest.fixture
def cert1():
    with open(opj(path_prefix_testin, 'cert1_redmineIdentineticsCom-cer.pem')) as fd:
        return fd.read()


@pytest.fixture
def namespaces7():
    return ['*.identinetics.com']


@pytest.fixture
def orgids7():
    return ['AT:VKZ:XFN-318886a']


@pytest.fixture
def signerCert7():
    with open(opj(path_prefix_testin, 'signercert7_rh.pem')) as fd:
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
