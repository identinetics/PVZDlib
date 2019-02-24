from pathlib import Path
from PVZDpy.config.pvzdlib_config_abstract import PVZDlibConfigAbstract
from PVZDpy.config.policystore_backend_file import PolicyStoreBackendFile


class PVZDlibConfig(PVZDlibConfigAbstract):
    """ Python configuration object for PVZDlib/PVZDpy """
    def _set_config(self):
        config = self.config['confkey']
        # Store policy artifacts in file system relative to this config
        config.polstore_dir = Path(__file__).parent / 'policystore/'
        config.polstore_backend = PolicyStoreBackendFile(config.polstore_dir)

        # Trusted Fedop Certificates: Always stored in filesystem
        config.trustedcertsdir = Path(__file__).parent / 'trustedcerts'

        config.xmlsign = True  # False: only for development to skip interactive signing
        config.debug = False
        config.projhome = Path('sys.argv[0]').parent.parent.parent.resolve()
