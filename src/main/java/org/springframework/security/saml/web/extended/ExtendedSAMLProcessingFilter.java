package org.springframework.security.saml.web.extended;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//@Component
public class ExtendedSAMLProcessingFilter extends AbstractAuthenticationProcessingFilter
{
    @Autowired
    @Qualifier(value = "extendedProcessor")
    protected SAMLProcessor processor;

    @Autowired
    @Qualifier(value = "extendedSAMLContextProviderV2")
    protected SAMLContextProvider contextProvider;

    /** * @param defaultFilterProcessesUrl the default value for filterProcessesUrl. */
    protected ExtendedSAMLProcessingFilter(String defaultFilterProcessesUrl)
    {
        super(defaultFilterProcessesUrl);
    }

    /** * URL for Web SSO profile responses or unsolicited requests */
    public static final String FILTER_URL = "/saml/SSO";

    public ExtendedSAMLProcessingFilter()
    {
        this(FILTER_URL);
    } /** * In case the login attribute is not present it is presumed that the call is made from the remote IDP * and contains a SAML assertion which is processed and authenticated. * * @param request request * @return authentication object in case SAML data was found and valid * @throws AuthenticationException authentication failure */

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException
    {
//        String entityId = "http://idp.ssocircle.com";
        String entityId = "http://www.okta.com/k3ubvdvHGIQJDVASUHJM";
//        String entityId = "http://WIN-E61QA275PHA.testad.newbay.com/adfs/services/trust";

        try
        {
            SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
            processor.retrieveMessage(context); // Override set values
            context.setCommunicationProfileId(getProfileName());
            context.setLocalEntityEndpoint(SAMLUtil.getEndpoint(context.getLocalEntityRoleMetadata().getEndpoints(), context.getInboundSAMLBinding(), getFilterProcessesUrl()));
            SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);

            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setIdpDiscoveryEnabled(false);
            extendedMetadata.setEcpEnabled(false);
            extendedMetadata.setSupportUnsolicitedResponse(false);
            context.setPeerExtendedMetadata(extendedMetadata);

            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
            SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
            EntityDescriptor entityDescriptor = builder.buildObject();
            entityDescriptor.setEntityID(entityId);
            context.setPeerEntityMetadata(entityDescriptor);

            return getAuthenticationManager().authenticate(token);
        } catch (SAMLException e) {
            logger.debug("Incoming SAML message is invalid", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid", e);
        } catch (MetadataProviderException e) {
            logger.debug("Error determining metadata contracts", e);
            throw new AuthenticationServiceException("Error determining metadata contracts", e);
        } catch (MessageDecodingException e) {
            logger.debug("Error decoding incoming SAML message", e);
            throw new AuthenticationServiceException("Error decoding incoming SAML message", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.debug("Incoming SAML message is invalid", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid", e);
        }
    } /** * Name of the profile this used for authentication. * * @return profile name */

    protected String getProfileName() { return SAMLConstants.SAML2_WEBSSO_PROFILE_URI; }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response)
    {
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request);
    } /*

    @Override public void afterPropertiesSet() { super.afterPropertiesSet(); Assert.notNull(processor, "SAMLProcessor must be set"); Assert.notNull(contextProvider, "Context provider must be set"); }*/
}
