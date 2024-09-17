<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/nmaprun">
	<root>
	<xsl:for-each select="host">
		<xsl:variable name="hostip" select="address/@addr"/>
		<xsl:for-each select="ports/port[state/@state!='closed']">
				<ip><xsl:value-of select="$hostip" /></ip>
				<port><xsl:value-of select="@portid" /></port>
				<state><xsl:value-of select="state/@state"/></state>
				<!--<xsl:value-of select="@protocol" /></port>-->
	  </xsl:for-each>
	</xsl:for-each>
</root>
</xsl:template>
</xsl:stylesheet>
