package org.springframework.security.saml.web.custom;

import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@Component(value = "customSAMLContextProvider")
public class CustomSAMLContextProvider implements SAMLContextProvider
{
    //private String spEntityId = "http://localhost:8090/demo/saml";

    @Autowired
    @Qualifier(value = "inMemoryMetadataManager")
    protected MetadataManager metadata;

    @Override
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        return null;
    }

    @Override
    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = new SAMLMessageContext();

        context.setLocalEntityId(metadata.getHostedSPName());
        context.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        return context;
    }
}
