<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">

  <xsl:template match="/">
    <xsl:copy-of select="//md:EntityDescriptor"></xsl:copy-of>
  </xsl:template>

</xsl:stylesheet>
