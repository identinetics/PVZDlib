import pathlib
import pytest
from cresignedxml_seclay_direct import cre_signedxml_seclay
from samlentitydescriptor import SAMLEntityDescriptorFromStrFactory


def assert_equal(expected, actual, fn=''):
    # workaround for assert because pycharm does not display the full string (despite pytest -vv etc.)
    msg = fn+"\n'"+actual+"' != '"+expected+"' "
    assert expected == actual, msg


@pytest.fixture
def path_testin():
    return pathlib.Path('testdata/saml')


@pytest.fixture
def path_testout():
    p = pathlib.Path('testout/cresignedxml')
    p.mkdir(exist_ok=True)
    return p


@pytest.fixture
def idp1_path_in(path_testin):
    return path_testin / 'unsigned_ed' / '01_idp1_valid_cert.xml'


@pytest.fixture
def idp1_path_out(path_testout):
    return path_testout / '01_idp1_valid_cert.xml'


@pytest.fixture
def idp22_path_in(path_testin):
    return path_testin / 'signed_ed' / '22_idp22_identinetics_valid.xml'


@pytest.fixture
def idp22_path_out(path_testout):
    return path_testout / '22_idp22_identinetics_valid.xml'


# enveloped signatures

def test_sign_idp_unsigned(idp1_path_in, idp1_path_out):
    ed = SAMLEntityDescriptorFromStrFactory(idp1_path_in.read_text())
    md_namespace_prefix = ed.get_namespace_prefix()
    ed_signed = cre_signedxml_seclay(
        ed.get_xml_str(),
        sig_type='enveloped',
        sig_position='/' + md_namespace_prefix + ':EntityDescriptor')
    idp1_path_out.write_text(ed_signed)
    # TODO: assert result (requires masking the xades SigningTime)


def test_sign_idp_signed_with_diacritics(idp22_path_in, idp22_path_out):
    ed = SAMLEntityDescriptorFromStrFactory(idp22_path_in.read_text())
    ed.remove_enveloped_signature()
    md_namespace_prefix = ed.get_namespace_prefix()
    ed_signed = cre_signedxml_seclay(
        ed.get_xml_str(),
        sig_type='enveloped',
        sig_position='/' + md_namespace_prefix + ':EntityDescriptor')
    idp22_path_out.write_text(ed_signed)
    # TODO: assert result (requires masking the xades SigningTime)


# TODO: test enveloping signature