""" create an invocation class specific for AODSFileHandler """
from .abstractinvocation import AbstractInvocation

class aodslhInvocation(AbstractInvocation):
    def __init__(self,
                 inputfilename = None,
                 noxmlsign = False,
                 journal = None,
                 poldirhtml = None,
                 poldirjson = None,
                 shibacl = None,
                 printtrustedcerts = False,
                 registrant = '',
                 submitter = '',
                 list_trustedcerts = False,
                 trustedcerts = None):

        self.inputfilename =      inputfilename
        self.noxmlsign =          noxmlsign
        self.journal =            journal
        self.poldirhtml =         poldirhtml
        self.poldirjson =         poldirjson
        self.shibacl =            shibacl
        self.printtrustedcerts =  printtrustedcerts
        self.registrant =         registrant
        self.submitter =          submitter
        self.list_trustedcerts =  list_trustedcerts
        self.trustedcerts =       trustedcerts
