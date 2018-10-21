import logging, os, re, sys
import lxml.etree
from .constants import *
from .userexceptions import *
from .xmlschemavalidator import XmlSchemaValidator
from .xy509cert import XY509cert

__author__ = 'r2h2'


class SAMLEntityDescriptor:
    def __init__(self,
                 ed_path=None,
                 createfromcertstr=None, entityid=None, samlrole=None):
        """ Create a SAMLEntityDescriptor with either of 2 methods:
                1. from a xml file with an EntityDescriptor as root element, or
                2. from a certificate + a saml role
        """
        if sum(x is not None for x in (ed_path, createfromcertstr)) != 1:
            raise InputValueError('one and only one argument out of (ed_path, createfromcertstr) is required')
        if ed_path is not None:   # case 1
            self.ed_path = ed_path
            self.ed_path_abs = os.path.abspath(ed_path)
            if not os.path.isfile(self.ed_path_abs) or os.path.getsize(self.ed_path_abs) == 0:
                raise EmptySamlEDError(self.ed_path_abs + ' empty or missing')
            assert self.ed_path_abs[-4:] == '.xml', 'input file must have the extension .xml'
            self.tree = lxml.etree.parse(self.ed_path_abs)
            self.xml_str = lxml.etree.tostring(self.tree, encoding='utf-8', pretty_print=False).decode('utf-8')
        elif createfromcertstr is not None:  # case 2
            if entityid is None or samlrole is None:
                raise InputValueError('if creating ed from certstr, entityid and samlrole must be given.')
            self.xml_str = self.cert2entitydescriptor(createfromcertstr, entityid, samlrole)
            self.rootelem = lxml.etree.fromstring(self.xml_str.encode('utf-8'))
            self.tree = self.rootelem.getroottree()
        if self.tree.getroot().tag != XMLNS_MD_PREFIX+'EntityDescriptor':
            raise InputValueError('XML file must have md:EntityDescriptor as root element')


    def get_entityid(self):
        return self.tree.getroot().attrib['entityID']


    def get_xml_str(self):
        xml_str = lxml.etree.tostring(self.tree, encoding='utf-8', pretty_print=False)
        return xml_str.decode('utf-8')


    def get_signing_certs(self, samlrole='IDP') -> [XY509cert]:
        x509certs = []
        #if samlrole not in ('any', 'IDP', 'SP'):
        #    raise InputValueError("samlrole must be on of 'any', 'IDP', 'SP'")
        if samlrole not in ('IDP', ):
            raise InputValueError("samlrole must be 'IDP'")
        idpssodesc = self.tree.xpath('//md:IDPSSODescriptor', namespaces={'md': XMLNS_MD})
        if len(idpssodesc) > 0:
            keydescriptors = idpssodesc[0].findall(XMLNS_MD_PREFIX+'KeyDescriptor')
            for kd in keydescriptors:
                if 'use' in kd.attrib and kd.attrib['use'] == 'encryption':
                    pass
                else:  # signing certs are those with use="signing" or have no use attribute
                    for x509cert in kd.iter(XMLNS_DSIG_PREFIX+'X509Certificate'):
                        x509certs.append(XY509cert(x509cert.text.strip()))
        return x509certs

    def validate_xsd(self):
        schema_dir_abs = os.path.join(PROJLIB, 'SAML_MD_Schema')
        saml_schema_validator = XmlSchemaValidator(schema_dir_abs)
        retmsg = saml_schema_validator.validate_xsd(self.ed_path_abs)
        if retmsg is not None:
            raise InvalidSamlXmlSchemaError('File ' + self.ed_path_abs +
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


    def modify_and_write_ed(self, fd):
        elemTree = lxml.etree.ElementTree(self.dom)
        elemTree.write(fd, encoding='utf-8', xml_declaration=True)
