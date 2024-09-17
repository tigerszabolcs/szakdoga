<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/nmaprun">
	<root>
	<xsl:for-each select="host">
		<xsl:variable name="hostip" select="address/@addr"/>
		<xsl:for-each select="ports/port">
			<xsl:variable name="port" select="@portid"/>
			<xsl:for-each select="script">
				<xsl:choose>
					<xsl:when test="table and table[@key='vulns']">
						<xsl:for-each select="table[@key='vulns']/table">
							<ip><xsl:value-of select="$hostip" /></ip>
							<port><xsl:value-of select="$port" /></port>
							<vulnerability><xsl:value-of select="elem[@key='title']" /></vulnerability>
							<description><xsl:value-of select= "table[@key='description']" /></description>
						</xsl:for-each>
					</xsl:when>
					<xsl:when test="(@id='http-server-header') or contains(@output,'Found') or contains(@output,'is enabled') or contains(@output,'interesting') or contains(@output,'not configured') or contains(@output,'VULNERABLE') or (@id='http-php-version') or (@id='http-security-headers') or contains(@output,'Valid credentials') or (@id='nfs-showmount') or (@id='http-wordpress-enum') or (@id='http-title') or contains(@output,'Authentication was not required') or (@id='http-unsafe-output-escaping') or (@id='ftp-syst') or contains(@output,'Potential Users') or contains(@output,'Possible sqli for queries')">
						<xsl:choose>
							<xsl:when test="contains(@output,'NOT VULNERABLE')">
								
							</xsl:when>
							<xsl:otherwise>
								<ip><xsl:value-of select="$hostip" /></ip>
								<port><xsl:value-of select="$port" /></port>
								<vulnerability><xsl:value-of select="@id" /></vulnerability>
								<description><xsl:value-of select="@output" /></description>
							</xsl:otherwise>
						</xsl:choose>
					</xsl:when>
				</xsl:choose>				
			</xsl:for-each>
	  </xsl:for-each> 
	</xsl:for-each>
	</root>
</xsl:template>
</xsl:stylesheet>