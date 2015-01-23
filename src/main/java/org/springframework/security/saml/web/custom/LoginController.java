package org.springframework.security.saml.web.custom;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/saml")
public class LoginController
{
    private final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    @Qualifier(value = "customSAMLContextProvider")
    protected SAMLContextProvider contextProvider;

    @Autowired
    protected WebSSOProfile webSSOprofile;

    @Autowired
    @Qualifier(value = "customWebSSOProfileOptions")
    protected WebSSOProfileOptions defaultOptions;

    @RequestMapping(value = "/auth")
    public void login(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException
    {
        try {
            SAMLMessageContext context = contextProvider.getLocalAndPeerEntity(httpServletRequest, httpServletResponse);

            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
            SAMLObjectBuilder<IDPSSODescriptor> builder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            IDPSSODescriptor idpssoDescriptor = builder.buildObject();
            SAMLObjectBuilder<SingleSignOnService> builderSSOService = (SAMLObjectBuilder<SingleSignOnService>) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
            SingleSignOnService ssoService = builderSSOService.buildObject();
            ssoService.setLocation(getRemoteIDP());
            ssoService.setBinding(getRemoteIDPBinding());
            idpssoDescriptor.getSingleSignOnServices().add(ssoService);

            context.setPeerEntityRoleMetadata(idpssoDescriptor);
            context.setPeerExtendedMetadata(new ExtendedMetadata());

            initiateSSO(context);
        } catch (SAMLException e1) {
            logger.debug("Error initializing entry point", e1);
            throw new ServletException(e1);
        } catch (MetadataProviderException e1) {
            logger.debug("Error initializing entry point", e1);
            throw new ServletException(e1);
        } catch (MessageEncodingException e1) {
            logger.debug("Error initializing entry point", e1);
            throw new ServletException(e1);
        }
    }

    private void initiateSSO(SAMLMessageContext context) throws SAMLException, MetadataProviderException, MessageEncodingException {
        webSSOprofile.sendAuthenticationRequest(context, defaultOptions);
    }

    private String getRemoteIDP() {
        return "https://synchronosssynchronoss.okta.com/app/synchronoss2_spuds_1/k3ubvdvHGIQJDVASUHJM/sso/saml";
    }

    private String getRemoteIDPBinding() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }
}
