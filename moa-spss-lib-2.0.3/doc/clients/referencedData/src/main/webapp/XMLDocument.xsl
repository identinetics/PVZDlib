<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:doc="urn:document">
  <xsl:output encoding="UTF-8" method="xml" indent="yes"/>
  <xsl:template match="/doc:XMLDocument">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <title>HTML-Dokument</title>
      </head>
      <body>
        <xsl:for-each select="doc:Paragraph">
          <p>
            <xsl:value-of select="child::text()"/>
          </p>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
