import logging, os, re, sys
import lxml.etree
from constants import PROJDIR_ABS, XMLNS_DSIG, XMLNS_MD
from userexceptions import *
from xmlschemavalidator import XmlSchemaValidator
from xy509cert import XY509cert

__author__ = 'r2h2'


class SAMLEntityDescriptor:
    def __init__(self,
                 ed_file_handle=None,
                 ed_bytes=None,
                 createfromcertstr=None, entityid=None, samlrole=None,
                 delete_entityid=None):
        """ Create a SAMLEntityDescriptor with either of 4 methods:
                1. from a xml file with an EntityDescriptor as root element, or
                2. from a certificate + a saml role, or
                3. from an entityID as a delete request
                4. from a string
        """
        if sum(x is not None for x in (ed_file_handle, createfromcertstr, delete_entityid, ed_bytes)) != 1:
            raise InputValueError('only one argument out of (ed_file_handle, createfromcertstr, '
                                  'delete_entityid, ed_bytes) allowed')
        if ed_file_handle is not None:   # case 1
            self.ed_file_handle = ed_file_handle
            self.ed_filename_abs = os.path.abspath(ed_file_handle.name)
            if not os.path.isfile(self.ed_filename_abs) or os.path.getsize(self.ed_filename_abs) == 0:
                raise EmptySamlEDError(self.ed_filename_abs + ' empty or missing')
            assert self.ed_filename_abs[-4:] == '.xml', 'input file must have the extension .xml'
            with open(self.ed_filename_abs, encoding='utf8') as f:
                self.xml_str = f.read()
        elif createfromcertstr is not None:  #case 2
            if entityid is None or samlrole is None:
                raise InputValueError('if creating ed from certstr, entityid and samlrole must be given.')
            self.xml_str = self.cert2entitydescriptor(createfromcertstr, entityid, samlrole)
        elif delete_entityid is not None: # case 3
            self.xml_str = self.create_delete(delete_entityid)
        else:  #case 4
            self.xml_str = ed_bytes
        self.dom = lxml.etree.fromstring(self.xml_str.encode('utf-8'))
        if self.dom.tag != XMLNS_MD + 'EntityDescriptor':
            raise InputValueError('XML file must have md:EntityDescriptor as root element')


    def get_entityid(self):
        return self.dom.attrib['entityID']


    def get_xml_str(self):
        return self.xml_str


    def get_signing_certs(self, samlrole='IDP') -> [XY509cert]:
        x509certs = []
        #if samlrole not in ('any', 'IDP', 'SP'):
        #    raise InputValueError("samlrole must be on of 'any', 'IDP', 'SP'")
        if samlrole not in ('IDP', ):
            raise InputValueError("samlrole must be 'IDP'")
        idpssodesc = self.dom.find(XMLNS_MD+'IDPSSODescriptor')
        if idpssodesc is not None:
            keydescriptors = idpssodesc.findall(XMLNS_MD+'KeyDescriptor')
            for kd in keydescriptors:
                if 'use' in kd.attrib and kd.attrib['use'] == 'encryption':
                    pass
                else:  # signing certs are those with use="signing" or have no use attribute
                    for x509cert in kd.iter(XMLNS_DSIG+'X509Certificate'):
                        x509certs.append(XY509cert(x509cert.text.strip()))
        return x509certs

    def validate_xsd(self):
        if self.ed_file_handle is None:
            raise InputValueError('validation not possible unless EntityDescriptor is passed as file')
        schema_dir_abs = os.path.join(PROJDIR_ABS, 'lib/SAML_MD_Schema')
        saml_schema_validator = XmlSchemaValidator(schema_dir_abs)
        retmsg = saml_schema_validator.validate_xsd(self.ed_filename_abs)
        if retmsg is not None:
            self.ed_file_handle.close()
            #sys.tracebacklimit = 1
            raise InvalidSamlXmlSchemaError('File ' + self.ed_filename_abs +
                                            ' is not schema valid:\n' + retmsg)

    def validate_schematron(self):
        pass  # TODO: implement


    def get_namespace_prefix(self) -> str:
        """
        Due to a limitation in the XML signer used here (SecurityLayer 1.2)
        the XPath expression for the enveloped signature is specified as
        namespace prefix. getNamespacePrefix extracts the prefix to be used
        in the XPath when calling the signature.
        This functions is using a regular expression, YMMV in corner cases.
        """
        p = re.compile('\sxmlns:(\w+)\s*=\s*"urn:oasis:names:tc:SAML:2.0:metadata"')
        m = p.search(self.xml_str)
        return m.group(1)


    def get_filename(self) -> str:
        """ remove non-alpha characters, uppercase first char after no-alpha;
            add _ after hostname and .xml as extension
        """
        x = re.sub(r'^https?://', '', self.get_entityid())
        r = ''
        upper = False
        in_path = False
        for i in range(0, len(x)):
            if x[i].isalpha() or x[i].isdigit():
                if upper:
                    r += x[i].upper()
                else:
                    r += x[i]
                upper = False
            elif not in_path and x[i] == '/':
                r += '_'
                in_path = True
            else:
                upper = True
        return r + '.xml'


    def verify_filename(self, filename):
        """ verify if filename maps the entityID. _Not_ call on object creation """
        basefn = os.path.basename(filename)
        # file name must have the format "VKZ.compressedEntityId.xml". check right substring:
        if not re.search(self.get_filename()+'$', basefn):
            raise InputValueError('Invalid format for EntitiyDescriptor filename "%s". The file name '
                                  'for entityID %s must end with "%s" - see PAtool documentation.' % \
                                  (basefn, self.get_entityid(), self.get_filename()))


    def cert2entitydescriptor(self, cert_str, entityid, samlrole):
        if samlrole == 'IDP':
            entityDescriptor = """\
<md:EntityDescriptor entityID="{eid}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:pvzd="http://egov.gv.at/pvzd1.xsd"
    pvzd:pvptype="R-Profile">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
           <ds:X509Certificate>
{pem}
           </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{eid}/idp/unused"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>""".format(eid=entityid, pem=cert_str)
        elif samlrole == 'SP':
            entityDescriptor = """\
<md:EntityDescriptor entityID="{eid}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:pvzd="http://egov.gv.at/pvzd1.xsd"
    pvzd:pvptype="R-Profile">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
           <ds:X509Certificate>
{pem}
           </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{eid}/acs/unused" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>""".format(eid=entityid, pem=cert_str)
        else:
            raise EntityRoleNotSupportedError("Only IDP and SP entity roles implemented, but %s given" % self.args.samlrole)
        return entityDescriptor

    def create_delete(self, entityid):
        entityDescriptor = """\
<!-- DELETE entity descriptor from metadata -->
<md:EntityDescriptor entityID="{eid}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:pvzd="http://egov.gv.at/pvzd1.xsd"
    pvzd:disposition="delete">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{eid}/idp/unused"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>""".format(eid=entityid)
        return entityDescriptor

    def modify_and_write_ed(self, fd):
        elemTree = lxml.etree.ElementTree(self.dom)
        elemTree.write(fd, encoding='utf-8', xml_declaration=True)
