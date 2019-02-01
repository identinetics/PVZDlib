""" create an invocation class specific for AODSFileHandler """
from .abstractinvocation import AbstractInvocation

class AodsfhInvocation(AbstractInvocation):
    def __init__(self, aods_filename, trustedcerts_filename):
        self.aods = aods_filename
        self.list_trustedcerts = False
        self.noxmlsign = False
        self.trustedcerts = trustedcerts_filename

