import json
import os
from pathlib import Path
import pytest
from PVZDpy.config.appconfig_abstract import PVZDlibConfigAbstract
from PVZDpy.trustedcerts import TrustedCerts
from PVZDpy.userexceptions import PolicyJournalNotInitialized

@pytest.fixture
def testdata_dir() -> Path:
    return Path('testdata/pvzdlib_config')

@pytest.fixture
def testout_dir() -> Path:
    dir = Path('testout/pvzdlib_config')
    dir.mkdir(parents=True, exist_ok=True)

@pytest.fixture
def expected_poldict_json02(testdata_dir):
    os.environ['PVZDLIB_CONFIG_MODULE'] = str(testdata_dir / 'pvzdlib_config02.py')
    p = testdata_dir/ 'expected_results' / 'policy_journal02.json'
    return json.load(p.open())


def test_01_default_not_init():
    pvzdconf = PVZDlibConfigAbstract.get_config()
    backend = pvzdconf.polstore_backend
    assert backend.get_policy_journal_path().name == 'policyjournal.xml'
    with pytest.raises(PolicyJournalNotInitialized) as context:
        _ = backend.get_policy_journal_json()

def test_02_init(expected_poldict_json02):
    pvzdconf = PVZDlibConfigAbstract.get_config()
    backend = pvzdconf.polstore_backend
    policy_journal_json = backend.get_policy_journal_json()
    assert json.loads(policy_journal_json) == expected_poldict_json02