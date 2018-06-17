<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:doc="urn:document" xmlns="http://www.w3.org/1999/xhtml">
  <xsl:output encoding="UTF-8" method="xml" indent="yes"/>
  <xsl:template match="/">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <title>HTML-Dokument</title>
      </head>
      <body>
        <xsl:apply-templates/> 
      </body>
    </html>
  </xsl:template>  
  <xsl:template match="doc:Paragraph">
    <p>
      <xsl:value-of select="child::text()"/>
    </p>
  </xsl:template>
</xsl:stylesheet>
