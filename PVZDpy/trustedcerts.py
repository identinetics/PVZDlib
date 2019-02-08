import logging
from PVZDpy.config.appconfig_abstract import PVZDlibConfigAbstract
from PVZDpy.userexceptions import ValidationError
from PVZDpy.xy509cert import XY509cert


class TrustedCerts:
    def __init__(self):
        self.pvzdconf = PVZDlibConfigAbstract.get_config()
        self._load_certlist_from_certdir()

    def _load_certlist_from_certdir(self):
        if not self.pvzdconf.trustedcertsdir.is_dir():
            raise ValidationError(f"Trusted Certs directory not found: {str(self.pvzdconf.trustedcertsdir)}")
        self.certs = set()
        for certfile in self.pvzdconf.trustedcertsdir.iterdir():
            if certfile.suffix == '.pem':
                pem = XY509cert.pem_remove_rfc7468_delimiters(
                    certfile.read_text(),
                    optional_delimiter=True)
                pem_single_line = pem.replace('\n', '').strip()
                self.certs.add(pem_single_line)
            else:
                logging.debug(f"skipping file in certdir because extension != '.pem': {certfile}")
