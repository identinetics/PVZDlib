""" create an invocation class specific for AODSFileHandler """
from pathlib import Path
from PVZDpy.config.policystore_backend_file import PolicyStoreBackendFile


class PVZDlibConfig():
    # Store policy artifacts in file system realitve to this config
    cd = Path(__file__).parent
    polstore_dir = cd / 'policystore/'
    polstore_backend = PolicyStoreBackendFile(polstore_dir)

    # Trusted Fedop Certificates: Always stored in filesystem
    trustedcertsdir = Path('/config/trustedcerts')

    xmlsign = True  # False only for development to skip interactive signing
    debug = False
