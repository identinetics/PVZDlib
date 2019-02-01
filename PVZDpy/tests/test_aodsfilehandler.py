import pytest
from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import AodsfhInvocation
from PVZDpy.userexceptions import ValidationError, UnauthorizedAODSSignerError

#path_prefix = 'PVZDpy/tests/testdata/aodsfilehandler/'
path_prefix = 'testdata/aodsfilehandler/'


def fixture_invocationargs(aods_filename, trustedcerts_filename):
    return AodsfhInvocation(path_prefix+aods_filename, path_prefix+trustedcerts_filename)


def test_authorized():
    args = fixture_invocationargs('pol_journal_sig_rh.xml', 'trustedcerts_rh.json')
    _ = AODSFileHandler(args).readFile()


def test_invalidsig():
    args = fixture_invocationargs('pol_journal_invalid_sig.xml', 'trustedcert_rh.json')
    with pytest.raises(ValidationError):
        _ = AODSFileHandler(args).readFile()


def test_unauthorized():
    args = fixture_invocationargs('pol_journal_sig_rh.xml', 'trustedcerts_pr.json')
    with pytest.raises(UnauthorizedAODSSignerError):
        _ = AODSFileHandler(args).readFile()
