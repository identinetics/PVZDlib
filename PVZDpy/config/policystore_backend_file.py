from pathlib import Path
from PVZDpy.config.policystore_backend_abstract import PolicyStoreBackendAbstract
from PVZDpy.userexceptions import PolicyJournalNotInitialized

class PolicyStoreBackendFile(PolicyStoreBackendAbstract):
    def __init__(self, polstore_dir: Path):
        polstore_dir.mkdir(parents=True, exist_ok=True)
        self.polstore_dir = polstore_dir
        self.p_journal_xml = polstore_dir / 'policyjournal.xml'
        self.p_journal_json = polstore_dir / 'policyjournal.json'
        self.p_dir_json = polstore_dir / 'policydict.json'
        self.p_dir_html = polstore_dir / 'policydict.html'
        self.shibacl = polstore_dir / 'shibacl.xml'
        self.trustedcertscopy = polstore_dir / 'trustedcerts.txt'

    # ---

    def get_policy_journal(self) -> bytes:
        if self.p_journal_xml.exists():
            return self.p_journal_xml.read_bytes()
        else:
            raise PolicyJournalNotInitialized

    def get_policy_journal_path(self) -> Path:
        return self.p_journal_xml

    def get_poldict_json(self) -> str:
        try:
            return self.p_dir_json.read_text()
        except FileNotFoundError as e:
            raise PolicyJournalNotInitialized

    def get_poldict_html(self) -> str:
        return self.p_dir_html.read_text()

    def get_shibacl(self) -> bytes:
        return self.shibacl.read_byteswrite()

    def get_trustedcerts_copy(self) -> str:
        return self.trustedcertscopy.read_text()

    # ---

    def set_policy_journal_xml(self, xml_bytes: str):
        if len(xml_bytes) > 0:
            self.p_journal_xml.write_bytes(xml_bytes)
        else:
            try:
                self.p_journal_xml.unlink()
            except FileNotFoundError:
                pass

    def set_policy_journal_json(self, json_str: str):
        self.p_journal_json.write_text(json_str)

    def set_poldict_json(self, json_str: str):
        self.p_dir_json.write_text(json_str)

    def set_poldict_html(self, html_str: str):
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
        self._unlink_ignore_notfound(self.p_journal_xml)
        self._unlink_ignore_notfound(self.p_dir_json)
        self._unlink_ignore_notfound(self.p_dir_html)
        self._unlink_ignore_notfound(self.shibacl)
