""" create an invocation class specific for AODSFileHandler """
from .abstractinvocation import AbstractInvocation

class AodslhInvocation(AbstractInvocation):
    def __init__(self,
                 inputfilename = None,
                 poldirhtml = None,
                 poldirjson = None,
                 shibacl = None,
                 printtrustedcerts = False,
                 registrant = '',
                 submitter = ''):
        self.inputfilename =      inputfilename
        self.poldirhtml =         poldirhtml
        self.poldirjson =         poldirjson
        self.shibacl =            shibacl
        self.printtrustedcerts =  printtrustedcerts
        self.registrant =         registrant
        self.submitter =          submitter
