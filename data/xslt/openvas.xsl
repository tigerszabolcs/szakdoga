<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
	<root>
	  <xsl:for-each select="report">
		  <xsl:for-each select="report">
		  <xsl:for-each select="results">
			  <xsl:for-each select="result[name!='Report outdated / end-of-life Scan Engine / Environment (local)']">
					<ip><xsl:value-of select="host/text()" /></ip>
					<port><xsl:value-of select="port" /></port>
					<vulnerability><xsl:value-of select="name" /></vulnerability>
					<severity><xsl:value-of select="nvt/severities/@score" /></severity>
					<description><xsl:value-of select="description" /></description>
			  </xsl:for-each>
		  </xsl:for-each>
		  </xsl:for-each>
	  </xsl:for-each>
  </root>
</xsl:template>

</xsl:stylesheet>
