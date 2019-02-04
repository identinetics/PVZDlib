from pathlib import Path


class PolicyStoreBackendAbstract():
    def get_policy_journal(self) -> bytes:
        # this shall implement PVZDpy.userexceptions.PolicyJournalNotInitialized
        raise NotImplementedError()

    def get_policy_journal_path(self) -> Path:
        raise NotImplementedError()

    def get_poldict_json(self) -> str:
        raise NotImplementedError()

    def get_poldict_html(self) -> str:
        raise NotImplementedError()

    def get_trustedcerts_copy(self) -> str:
        raise NotImplementedError()

    def get_shibacl(self) -> bytes:
        raise NotImplementedError()

    def set_policy_journal_xml(self):
        raise NotImplementedError()

    def set_policy_journal_json(self):
        raise NotImplementedError()

    def set_poldict_json(self):
        raise NotImplementedError()

    def set_poldict_html(self):
        raise NotImplementedError()

    def set_trustedcerts_copy(self):
        raise NotImplementedError()

    def set_shibacl(self):
        raise NotImplementedError()

    def reset_policy_and_derived(self):
        # delete data except for trustedcerts_copy
        raise NotImplementedError()


