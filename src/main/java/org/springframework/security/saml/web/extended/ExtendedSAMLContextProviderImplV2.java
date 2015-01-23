package org.springframework.security.saml.web.extended;

import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509CredentialNameEvaluator;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component(value = "extendedSAMLContextProviderV2")
public class ExtendedSAMLContextProviderImplV2 extends SAMLContextProviderImpl
{
    @Autowired
    protected KeyStoreCredentialResolver keyStoreCredentialResolver;

    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = new SAMLMessageContext();
        populateGenericContext(request, response, context);
        populateLocalEntityId(context, request.getRequestURI());
        populateLocalContext(context);
        populatePeerEntityId(context);
        return context;
    }

    protected void populateGenericContext(HttpServletRequest request, HttpServletResponse response, SAMLMessageContext context) throws MetadataProviderException {

        HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, request.isSecure());

        // Store attribute which cannot be located from InTransport directly
        request.setAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_CONTEXT_PATH, request.getContextPath());

        context.setMetadataProvider(metadata);
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);

        context.setMessageStorage(null);
    }

    protected void populateTrustEngine(SAMLMessageContext samlContext) {
        SignatureTrustEngine engine;
        if ("pkix".equalsIgnoreCase(samlContext.getLocalExtendedMetadata().getSecurityProfile())) {
            engine = new PKIXSignatureTrustEngine(pkixResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver(), pkixTrustEvaluator, new BasicX509CredentialNameEvaluator());
        } else {
            engine = new ExplicitKeySignatureTrustEngine(keyStoreCredentialResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        }
        samlContext.setLocalTrustEngine(engine);
    }

    protected void populatePeerEntityId(SAMLMessageContext context) throws MetadataProviderException {
        String entityId = "http://www.okta.com/k3ubvdvHGIQJDVASUHJM";
        context.setPeerEntityId(entityId);
        context.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
    }
}
