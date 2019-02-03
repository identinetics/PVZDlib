from pathlib import Path


class PolicyStoreBackendAbstract():

    def get_policy_journal(self) -> bytes:
        raise NotImplementedError()

    def get_policy_journal_path(self) -> Path:
        raise NotImplementedError()

    def get_poldir_json(self) -> str:
        raise NotImplementedError()

    def get_poldir_html(self) -> str:
        raise NotImplementedError()

    def get_trustedcerts_copy(self) -> str:
        raise NotImplementedError()

    def get_shibacl(self) -> bytes:
        raise NotImplementedError()

    def set_policy_journal(self):
        raise NotImplementedError()

    def set_poldir_json(self):
        raise NotImplementedError()

    def set_poldir_html(self):
        raise NotImplementedError()

    def set_trustedcerts_copy(self):
        raise NotImplementedError()

    def set_shibacl(self):
        raise NotImplementedError()

    def reset_policy_and_derived(self):
        # delete data except for trustedcerts_copy
        raise NotImplementedError()


