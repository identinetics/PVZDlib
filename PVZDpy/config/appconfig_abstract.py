import importlib.util
import os
from pathlib import Path


class PVZDlibConfigAbstract():
    '''
    Global application configuration
    This class uses the Borg Pattern:
        Keep shared state in a common class (monostate vs singleton - see http://www.aleax.it/5ep.html)
        Whenever an instance is created, state is shared at the class level
    '''

    class GenericConfig:
        ''' Class to hold whatever config attributes '''
        pass

    # must assign a dict to __dict__, but within the dict let's have the GenericConfig instance
    config = {'confkey': GenericConfig()}

    def __init__(self):
        self.__dict__ = self.config
        self._set_config()

    @staticmethod
    def get_config() -> GenericConfig:
        if 'PVZDLIB_CONFIG_MODULE' in os.environ:
            path = Path(os.environ["PVZDLIB_CONFIG_MODULE"])
            if path.is_file():
                spec = importlib.util.spec_from_file_location("config", path)
                config = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(config)
                app_config = config.PVZDlibConfig()
                return app_config.config['confkey']
            else:
                raise Exception(f"File specified by PVZDLIB_CONFIG_MODULE does not exist: {path}")
        else:
            import PVZDpy.config.pvzdlib_config_default
            app_config = PVZDpy.config.pvzdlib_config_default.PVZDlibConfig()
            return app_config.config['confkey']
