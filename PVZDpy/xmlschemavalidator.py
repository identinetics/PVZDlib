import os.path
from jnius import autoclass
from PVZDpy.constants import PROJLIB

__author__ = 'r2h2'


class XmlSchemaValidator:
    """    Validates XML schema using Xerces/Java    """
    def __init__(self, xsd_schema_dir):
        self.saml_xsd_dir = os.path.join(PROJLIB, xsd_schema_dir)
        # name of class in foo/bar/Baz form (not foo.bar.Baz)
        pvzd_verify_sig = 'at/wien/ma14/pvzd/validatexsd/XSDValidator'
        self.pyjnius_xsdvalidator = autoclass(pvzd_verify_sig)
        self.saml_xsd_validator = self.pyjnius_xsdvalidator(self.saml_xsd_dir, False)


    def validate_xsd(self, filename_abs):
        return self.saml_xsd_validator.validateSchema(filename_abs)

    def validate_schematron(self):
        pass  # TODO: implement

