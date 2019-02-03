from pathlib import Path
from PVZDpy.config.policystore_backend_abstract import PolicyStoreBackendAbstract

class PolicyStoreBackendFile(PolicyStoreBackendAbstract):
    def __init__(self, polstore_dir: Path):
        polstore_dir.mkdir(parents=True, exist_ok=True)
        self.polstore_dir = polstore_dir
        self.p_journal = polstore_dir / 'policyjournal.xml'
        self.p_dir_json = polstore_dir / 'poldir.json'
        self.p_dir_html = polstore_dir / 'poldir.html'
        self.shibacl = polstore_dir / 'shibacl.xml'
        self.trustedcertscopy = polstore_dir / 'trustedcerts.html'

    # ---

    def get_policy_journal(self) -> bytes:
        return self.p_journal.read_bytes()

    def get_policy_journal_path(self) -> Path:
        return self.p_journal

    def get_poldir_json(self) -> str:
        return self.p_dir_json.read_text()

    def get_poldir_html(self) -> str:
        return self.p_dir_html.read_text()

    def get_shibacl(self) -> bytes:
        return self.shibacl.read_byteswrite()

    def get_trustedcerts_copy(self) -> str:
        return self.trustedcertscopy.read_text()

    # ---

    def set_policy_journal(self, xml_bytes: str):
        self.p_journal.write_bytes(xml_bytes)

    def set_poldir_json(self, json_str: str):
        self.p_dir_json.write_text(json_str)

    def set_poldir_html(self, html_str: str):
        self.p_dir_html.write_text(html_str)

    def set_shibacl(self, xml_bytes: str):
        self.shibacl.write_bytes(xml_bytes)

    def set_trustedcerts_copy(self, t: str):
        self.trustedcertscopy.write_text(t)

    # ---

    def _unlink_ignore_notfound(self, p: Path):
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    # ---

    def reset_pjournal_and_derived(self):
        self._unlink_ignore_notfound(self.p_journal)
        self._unlink_ignore_notfound(self.p_dir_json)
        self._unlink_ignore_notfound(self.p_dir_html)
        self._unlink_ignore_notfound(self.shibacl)
