import json
import os
import pytest
from pathlib import Path
from PVZDpy.aodslisthandler import AodsListHandler
from PVZDpy.policychange import PolicyChangeList
from PVZDpy.userexceptions import HashChainError, InputFormatError, InputValueError, JSONdecodeError


def get_testdata_dir() -> Path:
    return Path('testdata/aodslisthandler')


def get_testout_dir() -> Path:
    dir = Path('testout/aodslisthandler')
    dir.mkdir(parents=True, exist_ok=True)


def set_config_file(filename: str):
    os.environ['PVZDLIB_CONFIG_MODULE'] = str(get_testdata_dir() / filename)


class SetupTest:
    def __init__(self, changelist_file, expected_poldict_file = None):
        self.changelist_path = get_testdata_dir() / 'changelists' / changelist_file
        if expected_poldict_file:
            p = get_testdata_dir() / 'expected_results' / expected_poldict_file
            self.expected_poldict = json.load(p.open())
        set_config_file('pvzdlib_config_no_sig.py')
        self.aodslh = AodsListHandler()
        self.aodslh.remove()
        self.changelist = PolicyChangeList()
        self.changelist.load(self.changelist_path)


def test_01_create_add_read_OK():
    test = SetupTest('append01_OK.json', 'poldict01.json')
    test.aodslh.append(test.changelist)
    poldict = test.aodslh.read()

    assert test.expected_poldict == poldict


def test_02_delete_non_exist_rec():
    test = SetupTest('append02_delete_non_exist_rec.json')
    with pytest.raises(InputValueError) as context:
        test.aodslh.append(test.changelist)


def test_03_delete_non_exist_org():
    test = SetupTest('append03_delete_non_exist_orgid.json')
    with pytest.raises(InputValueError) as context:
        test.aodslh.append(test.changelist)


def test_04_append_OK():
    test = SetupTest('append04_OK.json', 'poldict04.json')
    test.aodslh.append(test.changelist)
    poldict = test.aodslh.read()
    assert test.expected_poldict == poldict


def test_05_append_invalid_fk():
    test = SetupTest('append05_OK.json', 'poldict05.json')
    with pytest.raises(InputValueError) as context:
        test.aodslh.append(test.changelist)


def test_07_brokenjson():
    with pytest.raises(json.decoder.JSONDecodeError) as context:
        test = SetupTest('append07_brokenjson.json')


def test_10_noarray():
    test = SetupTest('append10_noarray.json')
    with pytest.raises(TypeError) as context:
        test.aodslh.append(test.changelist)


def test_11_pk_no_str():
    test = SetupTest('append11_pk_no_str.json')
    with pytest.raises(InputFormatError) as context:
        test.aodslh.append(test.changelist)
