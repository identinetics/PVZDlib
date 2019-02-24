from pathlib import Path
from PVZDpy.userexceptions import PolicyJournalNotInitialized


class PolicyStoreBackendAbstract():
    # concrete classes must not raise PolicyJournalNotInitialized during __init__()
    def __init__(self):
        raise NotImplementedError()

    def get_policy_journal_xml(self) -> bytes:
        try:
            raise NotImplementedError()
        except FileNotFoundError:   # customize this to actual storage
            raise PolicyJournalNotInitialized

    def get_policy_journal_path(self) -> Path:
        # if persistence is not in the filesystem (-> database), provide a temp copy in fs for signature verification
        raise NotImplementedError()

    def get_policy_journal_json(self) -> str:
        try:
            raise NotImplementedError()
        except FileNotFoundError:   # customize this to actual storage
            raise PolicyJournalNotInitialized

    def get_poldict_json(self) -> str:
        raise NotImplementedError()

    def get_poldict_html(self) -> str:
        raise NotImplementedError()

    def get_trustedcerts_report(self) -> str:
        raise NotImplementedError()

    def get_shibacl(self) -> bytes:
        raise NotImplementedError()

    def set_policy_journal_xml(self, xml_bytes: bytes):
        raise NotImplementedError()

    def set_policy_journal_json(self, json_str: str):
        raise NotImplementedError()

    def set_poldict_json(self, json_str: str):
        raise NotImplementedError()

    def set_poldict_html(self, html_str: str):
        raise NotImplementedError()

    def set_shibacl(self, xml_bytes: bytes):
        raise NotImplementedError()

    def set_trustedcerts_report(self, t: str):
        raise NotImplementedError()

    def reset_policy_and_derived(self):
        # delete data except for trustedcerts_copy
        raise NotImplementedError()
