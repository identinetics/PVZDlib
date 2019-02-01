""" create an invocation class specific for AODSFileHandler """
from .abstractinvocation import AbstractInvocation

class AodsfhInvocation(AbstractInvocation):
    def __init__(self, aods, trustedcerts, noxmlsign=False, list_trustedcerts=False, subcommand=None):
        self.aods = aods
        self.trustedcerts = trustedcerts
        self.list_trustedcerts = list_trustedcerts
        self.noxmlsign = noxmlsign
        self.subcommand = subcommand

