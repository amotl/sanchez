# this is a namespace package
from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

# initialize root object for configuration settings
from sanchez.utils.config import ConfigurationObject
config = ConfigurationObject()
