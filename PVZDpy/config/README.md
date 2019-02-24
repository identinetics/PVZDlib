# PVZDpy Library Configuration

## Design goals

- "Configuration" is a global unique thingy that you can access from anywhere
- The configuration source is to be determined by the environment 
- The config class allows to plug different storage backends.
- The configuration can be parametrized, e.g. to set the storage backend 
- Configuration shall be a specific class, not a dict with uncontrolled keys and value types


## Design approach

1. The configuration is defined with the class PVZDlibConfigAbstract and needs to be implemented for actual use.
2. Use the Borg pattern: Store the configuration object as value in the __dict__ of the config class.
3. The getter function PVZDlibConfigAbstract.get_config() will always return the identical configuration object


## Usage

* Implement:

        from PVZDpy.config.pvzdlib_config_abstract import PVZDlibConfigAbstract
        
        class PVZDlibConfig(PVZDlibConfigAbstract):
            # start with a copy of pvzdlib_config_default.py
         
* Set the env variable PVZDLIB_CONFIG_MODULE to the path of the configuration module. 
If unset, the default configuration used for unit testing is active.

* Obain the config object in the application module:

        pvzdconf = PVZDlibConfigAbstract.get_config()
 

### Storage backend
 
The default is file system based, but the application may use a database.
For this purpose it has to provide an implementation of PolicyStoreBackendAbstract.
When instantiating PVZDlibConfig, config.backend must be set to an instance of this class.  