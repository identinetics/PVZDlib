import base64, bz2, datetime, os, re, sys
import logging
import lxml.etree as ET
from constants import PROJDIR_ABS
import localconfig
from plugins.xmlsigverifyer_abstract import XmlSigVerifyerAbstract
from plugins.xmlsigverifyer_response import XmlSigVerifyerResponse
from userexceptions import *

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
    """ Python wrapper for the PvzdVerifySig Java class
    The Python/Java bridge is implemented with 2 different libraries, to be on the save side :-)
    If PYJNIUS_ACTIVATE is unset, it will use javabridge, otherwise pyjnius
    """
    def __init__(self):
        # name of class in foo/bar/Baz form (not foo.bar.Baz)
        # print(os.environ['CLASSPATH'])
        self.pvzd_verify_sig_pkg = 'at/wien/ma14/pvzd/verifysigapi'
        self.pvzd_verify_sig = self.pvzd_verify_sig_pkg + '/' + 'PvzdVerifySig'
        try:
            os.environ['PYJNIUS_ACTIVATE']
            from jnius import autoclass
            self.pywrapper = autoclass(self.pvzd_verify_sig)
        except KeyError:
            None

    def verify(self, xml_file_name) -> str:
        """ verify xmldsig and return signerCertificate """
        moaspss_conf = os.path.join(PROJDIR_ABS, 'conf/moa-spss/MOASPSSConfiguration.xml')
        log4j_conf   = os.path.join(PROJDIR_ABS, 'conf/log4j.properties')
        sig_doc      = xml_file_name
        #logging.debug('verifying signature of %s using moa-sp, config path=%s' % (sig_doc, moaspss_conf))

        try:
            os.environ['PYJNIUS_ACTIVATE']
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
        except KeyError:
            import javabridge
            # constructor takes three string parameters
            pvzdverifysig = javabridge.make_instance(self.pvzd_verify_sig,
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                 moaspss_conf, log4j_conf, sig_doc)
            # method verify returns response object
            response = javabridge.call(pvzdverifysig, "verify",
                "()" + "L" + self.pvzd_verify_sig_pkg + "/" + "PvzdVerifySigResponse;")
            if javabridge.get_field(response, "pvzdCode", "Ljava/lang/String;") != 'OK':
                raise ValidationError("Signature verification failed, code=" +
                    javabridge.get_field(response, "pvzdCode", "Ljava/lang/String;") + "; " +
                    javabridge.get_field(response, "pvzdMessage", "Ljava/lang/String;"))

        # Following "see-what-you-signed" principle use returned data from sig library
        signed_data_str = response.referencedata
        try:
            os.environ['PYJNIUS_ACTIVATE']
            r = XmlSigVerifyerResponse(signed_data_str, response.signerCertificateEncoded)
        except KeyError:
            import javabridge
            r = XmlSigVerifyerResponse(signed_data_str, javabridge.get_field(response, "signerCertificateEncoded", "Ljava/lang/String;"))
        return r
