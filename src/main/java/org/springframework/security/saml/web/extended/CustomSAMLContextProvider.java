package org.springframework.security.saml.web.extended;

import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component(value = "custom1SAMLContextProvider")
public class CustomSAMLContextProvider implements SAMLContextProvider, InitializingBean
{
    protected final static Logger logger = LoggerFactory.getLogger(CustomSAMLContextProvider.class);

    @Autowired
    private KeyManager keyManager;

    @Autowired
    protected KeyStoreCredentialResolver keyStoreCredentialResolver;

    @Autowired
    protected MetadataManager metadata;

    @Override
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = new SAMLMessageContext();
        populateGenericContext(request, response, context);
        populateLocalEntityId(context, request.getRequestURI());
//        populateLocalContext(context);
        return context;
    }

    protected void populateLocalEntityId(SAMLMessageContext context, String requestURI) throws MetadataProviderException {
        context.setLocalEntityId(metadata.getHostedSPName());
        context.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    protected void populateGenericContext(HttpServletRequest request, HttpServletResponse response, SAMLMessageContext context) throws MetadataProviderException {
        HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, request.isSecure());
        request.setAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_CONTEXT_PATH, request.getContextPath());
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);
        context.setMessageStorage(null);
    }

    @Override
    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        return null;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (keyStoreCredentialResolver == null) {
/*            KeyStoreCredentialResolver resolver = null;

            resolver = new KeyStoreCredentialResolver(((JKSKeyManager)keyManager).getKeyStore(), new HashMap<String, String>(){{
                put("apollo", "nalle123");
            }});

            resolver.setMeetAllCriteria(false);
            resolver.setUnevaluableSatisfies(true);
            this.keyStoreCredentialResolver = resolver;*/
        }
    }
}
