import pytest
from PVZDpy.userexceptions import ValidationError
from PVZDpy.xy509cert import XY509cert

#path_prefix = 'PVZDpy/tests/testdata/xy509cert/'
path_prefix = 'testdata/xy509cert/'


def fixture_cert_str(index: int) -> str:
    filename = (
        '00_dummy',
        '01_cert_with_delim.pem',
        '02_cert_no_delim.pem',
        '03_cert_no_delim_one_line.pem',
    )
    with open(path_prefix+filename[index]) as fd:
        s =  fd.read()
        return s

#def test_pem_add_rfc7468_delimiters():

def test_pem_remove_rfc7468_delimiters():
    cert_str1 = fixture_cert_str(1)
    pem = XY509cert.pem_remove_rfc7468_delimiters(cert_str1, optional_delimiter=True)
    assert pem == fixture_cert_str(2)
    with pytest.raises(ValidationError):
        pem = XY509cert.pem_remove_rfc7468_delimiters(fixture_cert_str(2), optional_delimiter=False)

#def test_getPEM_str():

#def test_getSubjectCN():

#def test_getSubject_str():

#def test_getIssuer_str():

#def test_notValidAfter():

#def test_notAfter_str():

#def test_isNotExpired():

#def test_get_serial_number_int():

#def test_get_serial_number_hex():

#def test_get_pubkey():

#def test_digest():
