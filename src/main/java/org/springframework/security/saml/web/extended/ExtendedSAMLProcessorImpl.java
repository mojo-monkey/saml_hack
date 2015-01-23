package org.springframework.security.saml.web.extended;

import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;

import javax.xml.namespace.QName;
import java.util.Collection;

//@Component(value = "extendedSAMLProcessor")
public class ExtendedSAMLProcessorImpl extends SAMLProcessorImpl
{
    private final static Logger log = LoggerFactory.getLogger(SAMLProcessorImpl.class);

    public ExtendedSAMLProcessorImpl(Collection<SAMLBinding> bindings) {
        super(bindings);
    }

    public SAMLMessageContext retrieveMessage(SAMLMessageContext samlContext, SAMLBinding binding) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

        log.debug("Retrieving message using binding {}", binding.getBindingURI());

        verifyContext(samlContext);
        populateSecurityPolicy(samlContext, binding);

        QName peerEntityRole = samlContext.getPeerEntityRole();
        if (peerEntityRole == null) {
            peerEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
        }
        samlContext.setPeerEntityRole(peerEntityRole);
        samlContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        samlContext.setInboundSAMLBinding(binding.getBindingURI());

        // Decode the message
        MessageDecoder decoder = binding.getMessageDecoder();
        decoder.decode(samlContext);

        //if (samlContext.getPeerEntityMetadata() == null) {
            //throw new MetadataProviderException("Metadata for issuer " + samlContext.getInboundMessageIssuer() + " wasn't found");
        //}

        //samlContext.setPeerEntityId(samlContext.getPeerEntityMetadata().getEntityID());
        //samlContext.setPeerExtendedMetadata(((MetadataManager) samlContext.getMetadataProvider()).getExtendedMetadata(samlContext.getPeerEntityId()));

        return samlContext;
    }
}
