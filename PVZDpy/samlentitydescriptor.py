import os
import re
import tempfile
import lxml.etree
from PVZDpy.constants import PROJLIB, XMLNS_DSIG, XMLNS_DSIG_PREFIX, XMLNS_MD, XMLNS_MD_PREFIX
import PVZDpy.lxml_helper as lxml_helper
from PVZDpy.userexceptions import EmptySamlEDError, EntityRoleNotSupportedError, InvalidSamlXmlSchemaError, \
    InputValueError, MultipleEntitiesNotAllowed
from PVZDpy.xmlschemavalidator import XmlSchemaValidator
from PVZDpy.xy509cert import XY509cert

__author__ = 'r2h2'


class SAMLEntityDescriptor:
    """
    Instance of plain SAML EntityDescriptor without deployment profile specific extensions
    (exception: pvzd:pvptype attribute)
    """

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
            self.tree = self.get_entitydescriptor(lxml.etree.parse(self.ed_path_abs))
            self.xml_str = lxml.etree.tostring(self.tree, encoding='utf-8',
                                               pretty_print=False).decode('utf-8')
        elif createfromcertstr is not None:  # case 2
            if entityid is None or samlrole is None:
                raise InputValueError('if creating ed from certstr, entityid and samlrole must be given.')
            self.xml_str = SAMLEntityDescriptor.cert2ed(createfromcertstr, entityid, samlrole)
            self.rootelem = lxml.etree.fromstring(self.xml_str.encode('utf-8'))
            self.tree = self.rootelem.getroottree()
        self.samlrole = samlrole

    @staticmethod
    def cert2ed(cert_str, entityid, samlrole):
        cert_str_nodelimiters = XY509cert.pem_remove_rfc7468_delimiters(cert_str,
                                                                        optional_delimiter=True)
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
    </md:EntityDescriptor>""".format(eid=entityid, pem=cert_str_nodelimiters)
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
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{eid}/acs/unused" index="0" isDefault="true"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>""".format(eid=entityid, pem=cert_str_nodelimiters)
        else:
            raise EntityRoleNotSupportedError(
                f"Only IDP and SP entity roles implemented, but %s given {samlrole}")
        return entityDescriptor

    def get_entitydescriptor(self, tree: lxml.etree.ElementTree) -> lxml.etree.ElementTree:
        if tree.getroot().tag == XMLNS_MD_PREFIX + 'EntityDescriptor':
            return tree
        elif tree.getroot().tag == XMLNS_MD_PREFIX + 'EntitiesDescriptor':
            entity_count = len(tree.findall(XMLNS_MD_PREFIX + 'EntityDescriptor'))
            if entity_count == 1:
                return lxml.etree.ElementTree(tree.getroot()[0])
            elif entity_count > 1:
                raise MultipleEntitiesNotAllowed
            else:
                raise InputValueError('Missing md:EntityDescriptor')
        else:
            raise InputValueError('XML file must have md:EntityDescriptor as root element')

    def get_entityid(self) -> str:
        return self.tree.getroot().attrib['entityID']

    @staticmethod
    def get_filename_from_entityid(entityid: str) -> str:
        """ remove non-alpha characters, uppercase first char after no-alpha;
            add _ after hostname and .xml as extension
        """
        x = re.sub(r'^https?://', '', entityid)
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

    @staticmethod
    def get_namespace_prefix(ed_str: str) -> str:
        """
        Due to a limitation in the XML signer used here (SecurityLayer 1.2)
        the XPath expression for the enveloped signature is specified as
        namespace prefix. getNamespacePrefix extracts the prefix to be used
        in the XPath when calling the signature.
        This functions is using a regular expression, YMMV in corner cases.
        """
        p = re.compile(r'\sxmlns:(\w+)\s*=\s*"urn:oasis:names:tc:SAML:2.0:metadata"')
        m = p.search(ed_str)
        return m.group(1)

    def get_signing_certs(self, samlrole:str = 'IDP') -> [XY509cert]:
        x509certs = []
        # if samlrole not in ('any', 'IDP', 'SP'):
        #     raise InputValueError("samlrole must be on of 'any', 'IDP', 'SP'")
        if samlrole not in ('IDP', ):
            raise InputValueError("samlrole must be 'IDP'")
        idpssodesc = self.tree.xpath('//md:IDPSSODescriptor', namespaces={'md': XMLNS_MD})
        if len(idpssodesc) > 0:
            keydescriptors = idpssodesc[0].findall(XMLNS_MD_PREFIX + 'KeyDescriptor')
            for kd in keydescriptors:
                if 'use' in kd.attrib and kd.attrib['use'] == 'encryption':
                    pass
                else:  # signing certs are those with use="signing" or have no use attribute
                    for x509cert in kd.iter(XMLNS_DSIG_PREFIX + 'X509Certificate'):
                        x509certs.append(XY509cert(x509cert.text.strip()))
        return x509certs

    def get_xml_str(self) -> str:
        xml_str = lxml.etree.tostring(self.tree, encoding='utf-8', pretty_print=False)
        return xml_str.decode('utf-8')

    @staticmethod
    def has_enveloped_signature(self) -> bool:
        lxml_helper.delete_element_if_existing(
            self.ed.tree,
            '/md:EntityDescriptor/ds:Signature',
            {'md': XMLNS_MD, 'ds': XMLNS_DSIG})

    def remove_enveloped_signature(self):
        lxml_helper.delete_element_if_existing(
            self.tree,
            '/md:EntityDescriptor/ds:Signature',
            {'md': XMLNS_MD, 'ds': XMLNS_DSIG})

    def validate_schematron(self):
        pass  # TODO: implement

    def validate_xsd(self):
        schema_dir_abs = os.path.join(PROJLIB, 'SAML_MD_Schema')
        saml_schema_validator = XmlSchemaValidator(schema_dir_abs)
        retmsg = saml_schema_validator.validate_xsd(self.ed_path_abs)
        if retmsg is not None:
            raise InvalidSamlXmlSchemaError(f"File {self.ed_path_abs} is not schema valid:\n{retmsg})")

    def write(self, filename: str):
        ''' CAVEAT: This function does not take the signed info part of an XML DSig-validated
            document, but uses the internal tree represenation initialized with XML-parsing the
            signed document. Processing a document after signature valideation mnust not use this
            function!
        '''
        self.tree.write(filename, encoding='utf-8', xml_declaration=True)


def SAMLEntityDescriptorFromStrFactory(ed_str: str) -> SAMLEntityDescriptor:
    ''' Create SamlEdValidator from string - only for utf-8 (default) XML encoding '''
    fd = tempfile.NamedTemporaryFile(mode='w', prefix='pvzd_', suffix='.xml', encoding='utf-8')
    fd.write(ed_str)
    fd.flush()
    ed = SAMLEntityDescriptor(fd.name)
    fd.close
    return ed
