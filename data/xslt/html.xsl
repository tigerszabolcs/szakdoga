<?xml version="1.0" ?> 
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:s="http://www.stylusstudio.com/xquery">
    <xsl:template match="/">
        <html>
            <head >
				<style>
					body{font-family:Calibri; font-size:12pt}
					.proof{font-size:9pt;}
				</style>
			</head>
            <body style= "margin: 0 auto; background-color: #f1f1f1">
				<xsl:for-each select="/root/VULNERABILITY/SCORE[not(.=preceding::*)]">
					<xsl:variable name="score" select="."/>
					<h1>
						<xsl:value-of select="."/> sérülékenységi érték
					</h1>
					<xsl:for-each select="/root/VULNERABILITY[SCORE=$score]">
						<h2>
							<xsl:value-of select="TITLEHU" /> - <xsl:value-of select="TITLE" /> 
						</h2>
						<p>
							<xsl:value-of select="DESCRIPTIONHU" /> 
						</p>
						<xsl:for-each select="HOSTLIST">
							<p>
								<b>Érintett hosztok:</b>
								<br/>
								<xsl:value-of select="HOST" />
							</p>
							<p>
								<b>Bizonyíték:</b>
								<br/>
								<pre style="background-color:#cacaca" class="proof">
									<xsl:value-of select="DESCRIPTION" /> 
								</pre>
							</p>
						</xsl:for-each>
					</xsl:for-each>
				</xsl:for-each>
				<xsl:for-each select="/root/VULNERABILITY[SCORE='None']">
					<h1>None sérülékenységi érték</h1>
					<h2>
						<xsl:value-of select="TITLE"/>
					</h2>
					<p>
						<xsl:value-of select="DESCRIPTIONHU" /> 
					</p>
					<xsl:for-each select="HOSTLIST">
						<p>
							<b>Érintett hosztok:</b>
							<br/>
							<xsl:value-of select="HOST" />
						</p>
						<p>
							<b>Bizonyíték:</b>
							<br/>
							<pre style="background-color:#cacaca" class="proof">
								<xsl:value-of select="DESCRIPTION" /> 
							</pre>
						</p>
					</xsl:for-each>
				</xsl:for-each>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>