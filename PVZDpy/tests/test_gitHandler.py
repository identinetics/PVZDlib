import filecmp
import git
import os
from os.path import join 
import pytest
import shutil
import tempfile
from PVZDpy.githandler import GitHandler
from PVZDpy.utilities import are_dir_trees_equal

#path_prefix = 'PVZDpy/tests/testdata/githandler/'
path_prefix = 'testdata/githandler/'

@pytest.fixture
def githandler(workdir):
    shutil.rmtree(workdir, ignore_errors=True)
    shutil.copytree(join(path_prefix, 'init_state'), workdir)
    pepout_dir = join(workdir, 'pepout')
    repo_dir_work = join(workdir, 'repo')
    repo = git.Repo.init(repo_dir_work)
    repo.index.add([join(repo_dir_work, '*')])
    repo.index.commit('initial testdata loaded')
    return GitHandler(repo_dir_work,
                      pepout_dir)


#def test_make_repo_dirs():


#def test_getRequestQueueItems():


def test00_move_to_deleted():
    expected_result = path_prefix + 'expected_result_00'
    with tempfile.TemporaryDirectory() as tmpdir:
        gh = githandler(tmpdir)
        gh.move_to_deleted('00_delete_ok_idpExampleCom_idpXml.xml', 'idpExampleCom_idpXml.xml')
        assert are_dir_trees_equal(tmpdir, expected_result)


def test01_move_to_published_and_pepout_new():
    expected_result = path_prefix + 'expected_result_01'
    with tempfile.TemporaryDirectory() as tmpdir:
        gh = githandler(tmpdir)
        gh.move_to_published_and_pepout(
            '01_valid_idpExampleOrg_idpXml.xml',
            'signature payload placeholder',
            'idpExampleOrg_idpXml.xml')
        assert are_dir_trees_equal(tmpdir, expected_result)


def test02_move_to_published_and_pepout_existing():
    expected_result = path_prefix + 'expected_result_02'
    with tempfile.TemporaryDirectory() as tmpdir:
        gh = githandler(tmpdir)
        gh.move_to_published_and_pepout(
            '02_valid_idpExampleCom_idpXml.xml',
            'signature payload placeholder',
            'idpExampleCom_idpXml.xml')
        assert are_dir_trees_equal(tmpdir, expected_result)


def test03_move_to_rejected():
    expected_result = path_prefix + 'expected_result_03'
    with tempfile.TemporaryDirectory() as tmpdir:
        gh = githandler(tmpdir)
        gh.move_to_rejected('03_invalid_request.xml')
        gh.add_reject_message('03_invalid_request.xml', 'some error message content')
        assert are_dir_trees_equal(tmpdir, expected_result)
