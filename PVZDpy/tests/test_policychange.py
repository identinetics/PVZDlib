import json
from pathlib import Path
import pytest
from PVZDpy.policychange import PolicyChangeList, PolicyChangeOrganization


testdata_dir = Path('testdata') / 'policychange'

@pytest.fixture
def expected_result01():
    with (testdata_dir / 'expected_result_01.json').open() as fd:
        return json.load(fd)


def test_01_changelist(expected_result01):
    policy_change_list = PolicyChangeList()
    additem = PolicyChangeOrganization('id44', 'cn_for_44', False)
    policy_change_list.append(additem)
    assert policy_change_list.dict2list_for_compare() == expected_result01


