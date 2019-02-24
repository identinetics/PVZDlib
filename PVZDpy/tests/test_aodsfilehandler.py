import json
import os
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
    aods = {"AODS": [{"content":["header","","contentfields"],"delete": False}]}
    poldict_json = '{"domain": {}, "issuer": {}, "organization": {}, "revocation": {}, "userprivilege": {}}'
    aodsfh.save_journal(aods)
    aodsfh.save_policydict_json(poldict_json)
    aodsfh.save_policydict_html('<html/>')
    aodsfh.save_shibacl(b'<root/>')
    aodsfh.save_trustedcerts_report('some text')
    policyjournal = aodsfh.read()
    policyjournal_expected = aodsfh.pvzdconf.polstore_backend.get_policy_journal_path().parent / 'policyjournal_expected.json'
    assert policyjournal == json.load(policyjournal_expected.open())