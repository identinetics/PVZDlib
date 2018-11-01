import pytest
from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.userexceptions import ValidationError, UnauthorizedAODSSignerError

#path_prefix = 'PVZDpy/tests/testdata/aodsfilehandler/'
path_prefix = 'testdata/aodsfilehandler/'

@pytest.fixture
def invocationargs(aods_filename, trustedcerts_filename):
    return aodsfhInvocation(path_prefix+aods_filename, path_prefix+trustedcerts_filename)

#     class Invocation:
#         def __init__(self, args):
#             self.args = args
#
#     class Args:
#         def __init__(self, aods_filename, trustedcerts_filename):
#             self.aods = path_prefix+aods_filename
#             self.verbose = False
#             self.list_trustedcerts = False
#             self.noxmlsign = False
#             self.trustedcerts = path_prefix+trustedcerts_filename
#
#     args = Args(aods_filename, trustedcerts_filename)
#     return Invocation(args)


def test_authorized():
    args = invocationargs('pol_journal_sig_rh.xml', 'trustedcerts_rh.json')
    _ = AODSFileHandler(args).readFile()

def test_invalidsig():
    args = invocationargs('pol_journal_invalid_sig.xml', 'trustedcert_rh.json')
    with pytest.raises(ValidationError):
        _ = AODSFileHandler(args).readFile()

def test_unauthorized():
    args = invocationargs('pol_journal_sig_rh.xml', 'trustedcerts_pr.json')
    with pytest.raises(UnauthorizedAODSSignerError):
        _ = AODSFileHandler(args).readFile()
