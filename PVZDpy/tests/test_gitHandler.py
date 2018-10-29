import filecmp
import os
import pytest
import shutil
import tempfile
from PVZDpy.githandler import GitHandler

#path_prefix = 'PVZDpy/tests/testdata/githandler/'
path_prefix = 'testdata/githandler/'

def are_dir_trees_equal(dir1, dir2) -> bool:
    """ Compare two directories recursively. Files in each directory are
        assumed to be equal if their names and contents are equal.
        @return: True if the directory trees are the same and  there were no errors
            while accessing the directories or files, False otherwise.
        Kudos to Mateusz Kobos: https://stackoverflow.com/questions/4187564/
    """
    dirs_cmp = filecmp.dircmp(dir1, dir2)
    if len(dirs_cmp.left_only)>0 or len(dirs_cmp.right_only)>0 or \
        len(dirs_cmp.funny_files)>0:
        return False
    (_, mismatch, errors) =  filecmp.cmpfiles(
        dir1, dir2, dirs_cmp.common_files, shallow=False)
    if len(mismatch)>0 or len(errors)>0:
        return False
    for common_dir in dirs_cmp.common_dirs:
        new_dir1 = os.path.join(dir1, common_dir)
        new_dir2 = os.path.join(dir2, common_dir)
        if not are_dir_trees_equal(new_dir1, new_dir2):
            return False
    return True

def opj(*args):
    return os.path.join(args[0], args[1])

@pytest.fixture
def githandler(tmpdir):
    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.copytree(opj(path_prefix, 'start_state'), tmpdir)
    os.rename(opj(tmpdir, 'repo/git_disabled'), opj(tmpdir, 'repo/.git'))
    return GitHandler(opj(tmpdir, 'repo'),
                          opj(tmpdir, 'pepout'),
                      verbose=True)


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


#def test_reset_repo_with_defined_testdata():


#def test_add_request_message(sef):
