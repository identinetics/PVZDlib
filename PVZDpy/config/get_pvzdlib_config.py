import importlib.util
import os
from pathlib import Path

def get_pvzdlib_config():
    if os.environ["PVZDLIB_CONFIG_MODULE"]:
        path = Path(os.environ["PVZDLIB_CONFIG_MODULE"])
        if path.is_file():
            spec = importlib.util.spec_from_file_location("config", path)
            config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config)
            pvzdlib_config = config.PVZDlibConfig()
            return pvzdlib_config
        else:
            raise Exception(f"File specified by PVZDLIB_CONFIG_MODULE does not exist: {path}")
    else:
        import PVZDpy.config.pvzdlib_config_default
        return PVZDpy.config.pvzdlib_config_default.PVZDlibConfigDefault()
