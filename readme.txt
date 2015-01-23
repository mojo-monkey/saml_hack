saml idp

free idps
http://stackoverflow.com/questions/1125915/can-you-recommend-a-saml-2-0-identity-provider-for-test

multiple idp metadata
http://stackoverflow.com/questions/25993110/spring-saml-security-multiple-idp-metadata-configuration-for-two-different-adf


how does dropbox upload idp metadata
okta public adp metadata


multi idp + metadata selection or request + assertion verification

how to discover metadata on request = assertion


any exmple of spring saml used with multi idp,xml files






http://localhost:8080/spring-security-saml2-sample/saml/web/metadata/login



-----------------------------------
KEY TOOL operations
-----------------------------------
keytool -import -alias http://idp.ssocircle.com -file /home/tdoyle/Downloads/idp.crt -keypass keypass -keystore samlKeystore.jks -storepass nalle123
keytool -list -keystore samlKeystore.jks -storepass nalle123



-------
OKTA IDP
-------
EntityID : http://www.okta.com/k3ubvdvHGIQJDVASUHJM
REDIRECT SSO : https://synchronosssynchronoss.okta.com/app/synchronoss2_spuds_1/k3ubvdvHGIQJDVASUHJM/sso/saml
massy
ferguson
Ilovespuds1
ferguson@mailinator.com


--------------
SSO CIRCLE IDP
-------------
EntityID :  http://idp.ssocircle.com
REDIRECT SSO : https://idp.ssocircle.com:443/sso/SSORedirect/metaAlias/ssocircle
joesoap
ilovespuds



----------------------------
NICE SALESFORCE SETUP PAGE
-----------------------------
http://login.salesforce.com/help/pdfs/en/salesforce_single_sign_on.pdf
http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated SSO:  Redirect/POST Bindings|outline





---------------------------------
Admin Console
---------------------------------
 (1) ORG SSO Configuration
     * IDP SSO URI
     * IDP entity / issues identifier
     * A PEM-encoded x509 certificate with the file extension .crt
     * sso enabled / disabled
     * option to allow th upload of idp metadata file and parse out the details above



 * EAS Service Provider http redirects to idp


-----------------
might need to cpnfigire the support binding for sso login url in adp (http-redirect / http-post)
