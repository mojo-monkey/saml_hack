package org.springframework.security.saml.web.extended;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.trust.CertPathPKIXTrustEvaluator;
import org.springframework.security.saml.trust.PKIXInformationResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@Component(value = "extendedSAMLContextProvider")
public class ExtendedSAMLContextProviderImpl extends SAMLContextProviderImpl
{
    protected KeyStoreCredentialResolver keyStoreCredentialResolver;
    protected void populatePeerContext(SAMLMessageContext samlContext) throws MetadataProviderException {

    }

    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = new SAMLMessageContext();
        populateGenericContext(request, response, context);
        populateLocalEntityId(context, request.getRequestURI());
        populateLocalContextSamlAssert(context);
        return context;
    }

    protected void populateLocalContextSamlAssert(SAMLMessageContext context) throws MetadataProviderException {
        populateLocalEntity(context);
        populateDecrypter(context);
        populateSSLCredential(context);
        populatePeerSSLCredential(context);
//        populateTrustEngineAssert(context);
        populateSSLTrustEngine(context);
        populateSSLHostnameVerifier(context);
    }

/*
    protected void populateTrustEngineAssert(SAMLMessageContext samlContext) {
        SignatureTrustEngine engine;
        if ("pkix".equalsIgnoreCase(samlContext.getLocalExtendedMetadata().getSecurityProfile())) {
            engine = new PKIXSignatureTrustEngine(pkixResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver(), pkixTrustEvaluator, new BasicX509CredentialNameEvaluator());
        } else {
            engine = new ExplicitKeySignatureTrustEngine(keyStoreCredentialResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        }
        samlContext.setLocalTrustEngine(engine);
    }
*/

    public void afterPropertiesSet() throws ServletException
    {
        Assert.notNull(keyManager, "Key manager must be set");

        if (keyStoreCredentialResolver == null) {
            KeyStoreCredentialResolver resolver = null;

            resolver = new KeyStoreCredentialResolver(((JKSKeyManager)keyManager).getKeyStore(), new HashMap<String, String>(){{
                put("apollo", "nalle123");
            }});

            resolver.setMeetAllCriteria(false);
            resolver.setUnevaluableSatisfies(true);
            this.keyStoreCredentialResolver = resolver;
        }

        Assert.notNull(keyManager, "Key manager must be set");
        Assert.notNull(metadata, "Metadata must be set");
        Assert.notNull(storageFactory, "MessageStorageFactory must be set");

        if (metadataResolver == null) {
            MetadataCredentialResolver resolver = new org.springframework.security.saml.trust.MetadataCredentialResolver(metadata, keyManager);
            resolver.setMeetAllCriteria(false);
            resolver.setUnevaluableSatisfies(true);
            this.metadataResolver = resolver;
        }

        if (pkixResolver == null) {
            pkixResolver = new PKIXInformationResolver(metadataResolver, metadata, keyManager);
        }

        if (pkixTrustEvaluator == null) {
            pkixTrustEvaluator = new CertPathPKIXTrustEvaluator();
        }

    }
}
