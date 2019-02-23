import json
import os
from pathlib import Path
import pytest
from PVZDpy.config.appconfig_abstract import PVZDlibConfigAbstract
from PVZDpy.trustedcerts import TrustedCerts
from PVZDpy.userexceptions import PolicyJournalNotInitialized


@pytest.fixture
def testdata_dir() -> Path:
    dir = Path('testdata/pvzdlib_config')
    dir.mkdir(parents=True, exist_ok=True)
    return dir


@pytest.fixture
def testout_dir() -> Path:
    dir = Path('testout/pvzdlib_config')
    dir.mkdir(parents=True, exist_ok=True)
    return dir


# --- 01 ---

def test_01_default_not_init():
    pvzdconf = PVZDlibConfigAbstract.get_config()
    backend = pvzdconf.polstore_backend
    assert backend.get_policy_journal_path().name == 'policyjournal.xml'
    with pytest.raises(PolicyJournalNotInitialized) as context:
        _ = backend.get_policy_journal_json()


# --- 02 ---

@pytest.fixture
def pvzdconfig02(testdata_dir):
    os.environ['PVZDLIB_CONFIG_MODULE'] = str(testdata_dir / 'pvzdlib_config02.py')


@pytest.fixture
def expected_poldict_json02(testdata_dir):
    p = testdata_dir/ 'expected_results' / 'policy_journal02.json'
    return json.load(p.open())


def test_02_read_existing(pvzdconfig02, expected_poldict_json02):
    pvzdconf = PVZDlibConfigAbstract.get_config()
    backend = pvzdconf.polstore_backend
    policy_journal_json = backend.get_policy_journal_json()
    assert json.loads(policy_journal_json) == expected_poldict_json02


# --- 03 ---

@pytest.fixture
def pvzdconfig03(testdata_dir):
    os.environ['PVZDLIB_CONFIG_MODULE'] = str(testdata_dir / 'pvzdlib_config03.py')


def test_03_initialize(pvzdconfig03):
    pvzdconf = PVZDlibConfigAbstract.get_config()
    backend = pvzdconf.polstore_backend
    try:
        pvzdconf.polstore_backend.reset_pjournal_and_derived()
    except PolicyJournalNotInitialized:  # customize this to actual storage
        pass

    backend.set_policy_journal_xml(b'\x00')
    backend.set_policy_journal_json('{"journaltestentry": ""}')
    backend.set_poldict_json('{"dicttestentry": ""}')
    backend.set_poldict_html('<html/>')
    backend.set_shibacl(b'\x01')
    backend.set_trustedcerts_report('lore ipsum')
    assert backend.get_policy_journal_xml() == b'\x00'
    assert backend.get_policy_journal_json() == '{"journaltestentry": ""}'
    assert backend.get_poldict_json() == '{"dicttestentry": ""}'
    assert backend.get_poldict_html() == '<html/>'
    assert backend.get_shibacl() == b'\x01'
    assert backend.get_trustedcerts_report() == 'lore ipsum'
