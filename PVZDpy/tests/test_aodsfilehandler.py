import os
#import pathlib
import pytest
from PVZDpy.aodsfilehandler import AodsFileHandler
from PVZDpy.userexceptions import ValidationError, UnauthorizedAODSSignerError

def set_config_file(filename: str):
    os.environ['PVZDLIB_CONFIG_MODULE'] = f"testdata/aodsfilehandler/{filename}"

def test_authorized():
    set_config_file('pvzdlib_config_ok.py')
    _ = AodsFileHandler().read()


def test_invalidsig():
    set_config_file('pvzdlib_config_invalid_sig.py')
    with pytest.raises(ValidationError):
        _ = AodsFileHandler().read()


def test_unauthorized():
    set_config_file('pvzdlib_config_unauthz_signer.py')
    with pytest.raises(UnauthorizedAODSSignerError):
        aodsfh = AodsFileHandler()
        _ = aodsfh.read()

@pytest.mark.requires_signature
def test_create_read():
    set_config_file('pvzdlib_config_new.py')
    aodsfh = AodsFileHandler()
    aodsfh.remove()
    aodsfh.save({'blah': 'blah'}, '<html/>', b'<root/>')
    poldir = aodsfh.read()
    poldir_expected = aodsfh.backend.get_policy_journal_path().parent / 'poldir_expected.json'
    assert poldir_expected.read_text() == aodsfh.backend.get_poldir_json()