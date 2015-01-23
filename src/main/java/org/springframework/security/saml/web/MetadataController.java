/* Copyright 2011 Vladimir Schafer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.web;

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

/**
 * Class allows manipulation of metadata from web UI.
 */
@Controller
@RequestMapping("/metadata")
public class MetadataController {

    private final Logger logger = LoggerFactory.getLogger(MetadataController.class);

    public static enum AllowedSSOBindings {
        SSO_POST, SSO_PAOS, SSO_ARTIFACT, HOKSSO_POST, HOKSSO_ARTIFACT
    }

    @Autowired
    @Qualifier(value = "extendedSAMLContextProviderV2")
    protected SAMLContextProvider contextProvider;

    @Autowired
    protected WebSSOProfile webSSOprofile;

    @RequestMapping(value = "/login")
    public void adminLogin(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException
    {
        /*
         * Below is created from info pulled from eos orgainstaion
         */
//        String ssoUri = "https://idp.ssocircle.com:443/sso/SSORedirect/metaAlias/ssocircle";
//        String ssoUri = "https://172.16.72.18/adfs/ls/";

        String ssoUri = "https://synchronosssynchronoss.okta.com/app/synchronoss2_spuds_1/k3ubvdvHGIQJDVASUHJM/sso/saml";
        String ssoBinding = SAMLConstants.SAML2_POST_BINDING_URI; // the binding configured in eos org for idp

        try {
            SAMLMessageContext context = contextProvider.getLocalAndPeerEntity(httpServletRequest, httpServletResponse);

            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
            SAMLObjectBuilder<IDPSSODescriptor> builder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            IDPSSODescriptor idpssoDescriptor = builder.buildObject();

            SAMLObjectBuilder<SingleSignOnService> builderSSOService = (SAMLObjectBuilder<SingleSignOnService>) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
            SingleSignOnService ssoService = builderSSOService.buildObject();
            ssoService.setLocation(ssoUri);
            ssoService.setBinding(ssoBinding);
            idpssoDescriptor.getSingleSignOnServices().add(ssoService);

            context.setPeerEntityRoleMetadata(idpssoDescriptor);
            context.setPeerExtendedMetadata(new ExtendedMetadata());

            initializeSSO(context);
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

    protected void initializeSSO(SAMLMessageContext context) throws MetadataProviderException, SAMLException, MessageEncodingException {
        // Generate options for the current SSO request
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        options.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        options.setForceAuthN(true);
        options.setIncludeScoping(false);

        // Ordinary WebSSO
        logger.debug("Processing SSO using WebSSO profile");
        webSSOprofile.sendAuthenticationRequest(context, options);
    }
}
