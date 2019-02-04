""" create an invocation class specific for AODSFileHandler """
import collections
from pathlib import Path
from PVZDpy.config.policystore_backend_file import PolicyStoreBackendFile

class PVZDlibConfig():
     # Store policy artifacts in file system relative to this config
     cd = Path(__file__).parent
     polstore_dir = cd.parent.parent / 'testout' / 'aodslisthandler' / 'policystore_ok'
     polstore_backend = PolicyStoreBackendFile(polstore_dir)

     # Trusted Fedop Certificates: Always stored in filesystem
     trustedcertsdir = cd / 'trustedcerts_rh'

     xmlsign = False  # False only for development to skip interactive signing
     debug = False
