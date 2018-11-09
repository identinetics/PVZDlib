from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.aodslisthandler import AodsListHandler


def get_policy_dict(self, invocation) -> dict:
    aodsFileHandler = AODSFileHandler(invocation.args)
    aodsListHandler = AodsListHandler(aodsFileHandler, invocation.args)
    return aodsListHandler.aods_read()


