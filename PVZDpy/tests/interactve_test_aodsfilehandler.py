import pytest
from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.aodslisthandler import *
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.userexceptions import ValidationError, UnauthorizedAODSSignerError

#path_prefix = 'PVZDpy/tests/testdata/aodsfilehandler/'
path_prefix = 'testdata/aodsfilehandler/'


def fixture_invocationargs(aods_filename, trustedcerts_filename):
    inv = aodsfhInvocation(path_prefix+aods_filename, path_prefix+trustedcerts_filename)
    inv.subcommand = 'scratch'
    return inv


def test_create():
    args = fixture_invocationargs('pol_journal_sig_empty.xml', 'trustedcerts_rh.json')
    aodsFileHandlder = AODSFileHandler(args)
    aodsListHandler = AodsListHandler(aodsFileHandlder, args)
    aodsListHandler.aods_scratch()
    aodsListHandler.aods_create()

