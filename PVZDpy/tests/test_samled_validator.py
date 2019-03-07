import json
from os.path import join as opj
import os
# from PVZDpy.constants import *
from PVZDpy.samled_validator import SamlEdValidator
from PVZDpy.tests.common_fixtures import ed_path, path_prefix_testin, path_prefix_testout
from PVZDpy.tests.common_fixtures import policydict_plain1, policydict1 # NOQA


def assert_equal(expected, actual, fn=''):
    # workaround because pycharm does not display the full string (despite pytest -vv etc)
    msg = fn + "\n'" + actual + "' != '" + expected + "' "
    assert expected == actual, msg


def ed_path_testin(file_index: int):
    return ed_path(file_index)


def ed_path_testout(file_index: int, test_index: int):
    os.makedirs(path_prefix_testout, exist_ok=True)
    return opj(path_prefix_testout, 'test{:02d}_ed{:02d}.json'.format(test_index, file_index))


def ed_path_test_expected(file_index: int, test_index: int):
    return opj(path_prefix_testin, 'samled_val_expected_results',
               'test{:02d}_ed{:02d}.json'.format(test_index, file_index))


def run_test_with_edpath(file_index: int, policystore, sigval=False, test_index=None):
    ed = SamlEdValidator(policystore)
    ed.validate_entitydescriptor(ed_path_new=ed_path_testin(file_index), portaladmin_sigval=sigval)
    ed_dict = ed.get_obj_as_dict()
    fn1_testout = ed_path_testout(file_index, test_index)
    fn2_testexp = ed_path_test_expected(file_index, test_index)
    with open(fn1_testout, 'w') as fd1:
        fd1.write(json.dumps(ed_dict, indent=2, sort_keys=True))
    with open(fn1_testout) as fd1:
        with open(fn2_testexp) as fd2:
            # assert fd2.read() == fd1.read()
            assert_equal(fd2.read(), fd1.read(), fn=fn1_testout)
    os.unlink(fn1_testout)


def test01_edval_edpath1(policydict1):
    run_test_with_edpath(1, policydict1, sigval=False, test_index=1)


def test01_edval_edpath2(policydict1):
    run_test_with_edpath(2, policydict1, sigval=False, test_index=1)


def test01_edval_edpath3(policydict1):
    run_test_with_edpath(3, policydict1, sigval=False, test_index=1)


def test01_edval_edpath4(policydict1):
    run_test_with_edpath(4, policydict1, sigval=False, test_index=1)


def test01_edval_edpath5(policydict1):
    run_test_with_edpath(5, policydict1, sigval=False, test_index=1)


def test01_edval_edpath6(policydict1):
    run_test_with_edpath(6, policydict1, sigval=False, test_index=1)


def test01_edval_edpath7(policydict1):
    run_test_with_edpath(7, policydict1, sigval=False, test_index=1)


def test01_edval_edpath8(policydict1):
    run_test_with_edpath(8, policydict1, sigval=True, test_index=1)


def test01_edval_edpath9(policydict1):
    run_test_with_edpath(9, policydict1, sigval=True, test_index=1)


def test01_edval_edpath10(policydict1):
    run_test_with_edpath(10, policydict1, sigval=True, test_index=1)


def test01_edval_edpath11(policydict1):
    run_test_with_edpath(11, policydict1, sigval=True, test_index=1)


def test01_edval_edpath12(policydict1):
    run_test_with_edpath(12, policydict1, sigval=True, test_index=1)


def test01_edval_edpath13(policydict1):
    run_test_with_edpath(13, policydict1, sigval=True, test_index=1)


def test01_edval_edpath21(policydict1):
    run_test_with_edpath(21, policydict1, sigval=True, test_index=1)


def test01_edval_edpath22(policydict1):
    run_test_with_edpath(22, policydict1, sigval=True, test_index=1)


def test01_edval_edpath23(policydict1):
    run_test_with_edpath(23, policydict1, sigval=True, test_index=1)


def run_test_with_xmlstr(file_index: int, policystore, sigval=False, test_index=None):
    ed = SamlEdValidator(policystore)
    with open(ed_path_testin(file_index)) as fd:
        ed.validate_entitydescriptor(ed_str_new=fd.read(), portaladmin_sigval=sigval)
    ed_dict = ed.get_obj_as_dict()
    fn1_testout = ed_path_testout(file_index, test_index)
    fn2_testexp = ed_path_test_expected(file_index, test_index)
    with open(fn1_testout, 'w') as fd1:
        fd1.write(json.dumps(ed_dict, indent=2, sort_keys=True))
    with open(fn1_testout) as fd1:
        with open(fn2_testexp) as fd2:
            assert fd2.read() == fd1.read()
    os.unlink(fn1_testout)


def test02_edval_str01(policydict1):
    run_test_with_xmlstr(1, policydict1, sigval=False, test_index=2)


def test02_edval_str02(policydict1):
    run_test_with_xmlstr(2, policydict1, sigval=False, test_index=2)


def test02_edval_str03(policydict1):
    run_test_with_xmlstr(3, policydict1, sigval=False, test_index=2)


def test02_edval_str04(policydict1):
    run_test_with_xmlstr(4, policydict1, sigval=False, test_index=2)


def test02_edval_str05(policydict1):
    run_test_with_xmlstr(5, policydict1, sigval=False, test_index=2)


def test02_edval_str06(policydict1):
    run_test_with_xmlstr(6, policydict1, sigval=False, test_index=2)


def test02_edval_str07(policydict1):
    run_test_with_xmlstr(7, policydict1, sigval=False, test_index=2)


def test02_edval_str08(policydict1):
    run_test_with_xmlstr(8, policydict1, sigval=True, test_index=2)


def test02_edval_str09(policydict1):
    run_test_with_xmlstr(9, policydict1, sigval=True, test_index=2)


def test02_edval_str10(policydict1):
    run_test_with_xmlstr(10, policydict1, sigval=True, test_index=2)


def test02_edval_str11(policydict1):
    run_test_with_xmlstr(11, policydict1, sigval=True, test_index=2)


def test02_edval_st12(policydict1):
    run_test_with_xmlstr(12, policydict1, sigval=True, test_index=2)


def test02_edval_str13(policydict1):
    run_test_with_xmlstr(13, policydict1, sigval=True, test_index=2)


def test03_edval_str_unsigned(policydict1):
    run_test_with_xmlstr(18, policydict1, sigval=True, test_index=3)
