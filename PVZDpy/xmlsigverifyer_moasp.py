import base64, bz2, datetime, os, re, sys
import logging
import lxml.etree as ET
from jnius import autoclass
from PVZDpy.constants import PROJLIB
from PVZDpy.xmlsigverifyer_abstract import XmlSigVerifyerAbstract
from PVZDpy.xmlsigverifyer_response import XmlSigVerifyerResponse
from PVZDpy.userexceptions import *

__author__ = 'r2h2'


# style sheet to filter ds:Signature elements
xslt_str = """<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <xsl:template match="node() | @*">
    <xsl:copy>
      <xsl:apply-templates select="node() | @*"/>
    </xsl:copy>
  </xsl:template>
  <xsl:template match="ds:Signature"/>
</xsl:stylesheet>
"""

class XmlSigVerifyerMoasp(XmlSigVerifyerAbstract):
    """ Python wrapper for the PvzdVerifySig Java class """
    def __init__(self):
        # name of class in foo/bar/Baz form (not foo.bar.Baz)
        # print(os.environ['CLASSPATH'])
        self.pvzd_verify_sig_pkg = 'at/wien/ma14/pvzd/verifysigapi'
        self.pvzd_verify_sig = self.pvzd_verify_sig_pkg + '/' + 'PvzdVerifySig'
        self.pywrapper = autoclass(self.pvzd_verify_sig)

    def verify(self, xml_file_name) -> str:
        """ verify xmldsig and return signerCertificate """
        moaspss_conf = os.path.join(PROJLIB, 'moa-spss.conf/MOASPSSConfiguration.xml')
        log4j_conf   = os.path.join(PROJLIB, 'log4jconf/log4j.properties')
        sig_doc      = xml_file_name
        #logging.debug('verifying signature of %s using moa-sp, config path=%s' % (sig_doc, moaspss_conf))
        pvzdverifysig = self.pywrapper(
            moaspss_conf,
            log4j_conf,
            sig_doc)
        response  = pvzdverifysig.verify()
        if response.pvzdCode != 'OK':
            logging.debug("Signature verification failed, code=" +
                                  response.pvzdCode + "; " + response.pvzdMessage)
            raise ValidationError("Signature verification failed, code=" +
                                  response.pvzdCode + "; " + response.pvzdMessage)

        # Following "see-what-you-signed" principle use returned data from sig library
        signed_data_str = response.referencedata
        r = XmlSigVerifyerResponse(signed_data_str, response.signerCertificateEncoded)
        return r
