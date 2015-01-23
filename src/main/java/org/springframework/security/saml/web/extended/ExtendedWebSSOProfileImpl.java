package org.springframework.security.saml.web.extended;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.stereotype.Component;

@Component(value = "extendedWebSSOProfile")
public class ExtendedWebSSOProfileImpl extends WebSSOProfileImpl{
    public void sendAuthenticationRequest(SAMLMessageContext context, WebSSOProfileOptions options) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // Verify we deal with a local SP
        if (!SPSSODescriptor.DEFAULT_ELEMENT_NAME.equals(context.getLocalEntityRole())) {
            throw new SAMLException("WebSSO can only be initialized for local SP, but localEntityRole is: " + context.getLocalEntityRole());
        }

        // Load the entities from the context
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
//        IDPSSODescriptor idpssoDescriptor = (IDPSSODescriptor) context.getPeerEntityRoleMetadata();

/*        IDPSSODescriptor idpssoDescriptor = new IDPSSODescriptorImpl(
                "urn:oasis:names:tc:SAML:2.0:metadata",
                "IDPSSODescriptor",
                "md");
        */


        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<IDPSSODescriptor> builder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        IDPSSODescriptor idpssoDescriptor = builder.buildObject();
 //       idpssoDescriptor.setWantAuthnRequestsSigned(false);
//        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        ExtendedMetadata idpExtendedMetadata = new ExtendedMetadata();

//        if (spDescriptor == null || idpssoDescriptor == null || idpExtendedMetadata == null) {
//            throw new SAMLException("SPSSODescriptor, IDPSSODescriptor or IDPExtendedMetadata are not present in the SAMLContext");
//        }

//        SingleSignOnService ssoService = getSingleSignOnService(options, idpssoDescriptor, spDescriptor);
//        AssertionConsumerService consumerService = getAssertionConsumerService(options, idpssoDescriptor, spDescriptor);


        SAMLObjectBuilder<SingleSignOnService> builderSSOService = (SAMLObjectBuilder<SingleSignOnService>) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        SingleSignOnService ssoService = builderSSOService.buildObject();
//        ssoService.setLocation("https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php");
        ssoService.setLocation("https://idp.ssocircle.com:443/sso/SSORedirect/metaAlias/ssocircle");
        ssoService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        SAMLObjectBuilder<AssertionConsumerService> builderACSService = (SAMLObjectBuilder<AssertionConsumerService>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        AssertionConsumerService consumerService = builderACSService.buildObject();
        consumerService.setLocation("http://localhost:8080/spring-security-saml2-sample/saml/SSO");
        consumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        AuthnRequest authRequest = getAuthnRequest(context, options, consumerService, ssoService);
        // TODO optionally implement support for conditions, subject

        context.setCommunicationProfileId(getProfileIdentifier());
        context.setOutboundMessage(authRequest);
        context.setOutboundSAMLMessage(authRequest);
        context.setPeerEntityEndpoint(ssoService);
        context.setPeerEntityRoleMetadata(idpssoDescriptor);
//        context.setPeerExtendedMetadata(idpExtendedMetadata);

        if (options.getRelayState() != null) {
            context.setRelayState(options.getRelayState());
        }

        boolean sign = spDescriptor.isAuthnRequestsSigned() || idpssoDescriptor.getWantAuthnRequestsSigned();
        sendMessage(context, sign);

        SAMLMessageStorage messageStorage = context.getMessageStorage();
        if (messageStorage != null) {
            messageStorage.storeMessage(authRequest.getID(), authRequest);
        }
    }
}
