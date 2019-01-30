import pytest
from pathlib import Path
from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.userexceptions import ValidationError, UnauthorizedAODSSignerError

#path_prefix = 'PVZDpy/tests/testdata/aodsfilehandler/'
path_prefix = 'testdata/aodsfilehandler/'


def fixture_invocationargs(aods_filename, trustedcerts_filename):
    aods_fn_path = Path(path_prefix) / aods_filename
    return aodsfhInvocation(aods_fn_path, path_prefix+trustedcerts_filename)

#     class Invocation:
#         def __init__(self, args):
#             self.args = args
#
#     class Args:
#         def __init__(self, aods_filename, trustedcerts_filename):
#             self.aods = path_prefix+aods_filename
#             self.list_trustedcerts = False
#             self.noxmlsign = False
#             self.trustedcerts = path_prefix+trustedcerts_filename
#
#     args = Args(aods_filename, trustedcerts_filename)
#     return Invocation(args)


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
