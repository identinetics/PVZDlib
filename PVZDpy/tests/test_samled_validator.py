import json
import lxml.etree
from os.path import join as opj
import os
import pytest
import tempfile
from PVZDpy.constants import *
from PVZDpy.userexceptions import *
from PVZDpy.samled_validator import SamlEdValidator
from PVZDpy.tests.common_fixtures import *

def assert_equal(expected, actual):
    # workaround because pycharm does not display the full string (despite pytest -vv etc)
    msg = "'"+actual+"' != '"+expected+"'"
    assert expected == actual, msg

def ed_path_testin(file_index: int):
    return ed_path(file_index)

def ed_path_testout(file_index: int, test_index: int):
    os.makedirs(path_prefix_testout, exist_ok=True)
    return opj(path_prefix_testout, 'test{:02d}_ed{:02d}.json'.format(test_index, file_index))

def ed_path_test_expected(file_index: int, test_index: int):
    return opj(path_prefix_testin, 'samled_val_expected_results',
               'test{:02d}_ed{:02d}.json'.format(test_index, file_index))

def run_test_with_edpath(file_index: int, sigval=False, test_index=None):
    ed = SamlEdValidator(poldir1())
    ed.validate_entitydescriptor(ed_path_new=ed_path_testin(file_index), sigval=sigval)
    ed_dict = ed.get_obj_as_dict()
    fn1_testout = ed_path_testout(file_index, test_index)
    fn2_testexp = ed_path_test_expected(file_index, test_index)
    with open(fn1_testout, 'w') as fd1:
        fd1.write(json.dumps(ed_dict, indent=2, sort_keys=True))
    with open(fn1_testout) as fd1:
        with open(fn2_testexp) as fd2:
            #assert fd1.read() == fd2.read()
            assert_equal(fd1.read(), fd2.read())
    os.unlink(fn1_testout)

def test01_edval_edpath1():
    run_test_with_edpath(1, sigval=False, test_index=1)

def test01_edval_edpath2():
    run_test_with_edpath(2, sigval=False, test_index=1)

def test01_edval_edpath3():
    run_test_with_edpath(3, sigval=False, test_index=1)

def test01_edval_edpath4():
    run_test_with_edpath(4, sigval=False, test_index=1)

def test01_edval_edpath5():
    run_test_with_edpath(5, sigval=False, test_index=1)

def test01_edval_edpath6():
    run_test_with_edpath(6, sigval=False, test_index=1)

def test01_edval_edpath7():
    run_test_with_edpath(7, sigval=False, test_index=1)

def test01_edval_edpath8():
    run_test_with_edpath(8, sigval=True, test_index=1)

def test01_edval_edpath9():
    run_test_with_edpath(9, sigval=True, test_index=1)

def test01_edval_edpath10():
    run_test_with_edpath(10, sigval=True, test_index=1)

def test01_edval_edpath11():
    run_test_with_edpath(11, sigval=True, test_index=1)

def test01_edval_edpath12():
    run_test_with_edpath(12, sigval=True, test_index=1)

def test01_edval_edpath13():
    run_test_with_edpath(13, sigval=True, test_index=1)

def test01_edval_edpath21():
    run_test_with_edpath(21, sigval=True, test_index=1)

def run_test_with_xmlstr(file_index: int, sigval=False, test_index=None):
    ed = SamlEdValidator(poldir1())
    with open(ed_path_testin(file_index)) as fd:
        ed.validate_entitydescriptor(ed_str_new=fd.read(), sigval=sigval)
    ed_dict = ed.get_obj_as_dict()
    fn1_testout = ed_path_testout(file_index, test_index)
    fn2_testexp = ed_path_test_expected(file_index, test_index)
    with open(fn1_testout, 'w') as fd1:
        fd1.write(json.dumps(ed_dict, indent=2, sort_keys=True))
    with open(fn1_testout) as fd1:
        with open(fn2_testexp) as fd2:
            assert fd1.read() == fd2.read()
    os.unlink(fn1_testout)

def test02_edval_str01():
    run_test_with_xmlstr(1, sigval=False, test_index=2)

def test02_edval_str02():
    run_test_with_xmlstr(2, sigval=False, test_index=2)

def test02_edval_str03():
    run_test_with_xmlstr(3, sigval=False, test_index=2)

def test02_edval_str04():
    run_test_with_xmlstr(4, sigval=False, test_index=2)

def test02_edval_str05():
    run_test_with_xmlstr(5, sigval=False, test_index=2)

def test02_edval_str06():
    run_test_with_xmlstr(6, sigval=False, test_index=2)

def test02_edval_str07():
    run_test_with_xmlstr(7, sigval=False, test_index=2)

def test02_edval_str08():
    run_test_with_xmlstr(8, sigval=True, test_index=2)

def test02_edval_str09():
    run_test_with_xmlstr(9, sigval=True, test_index=2)

def test02_edval_str10():
    run_test_with_xmlstr(10, sigval=True, test_index=2)

def test02_edval_str11():
    run_test_with_xmlstr(11, sigval=True, test_index=2)

def test02_edval_st12():
    run_test_with_xmlstr(12, sigval=True, test_index=2)

def test02_edval_str13():
    run_test_with_xmlstr(13, sigval=True, test_index=2)

def test03_edval_str_unsigned():
    run_test_with_xmlstr(18, sigval=True, test_index=3)
