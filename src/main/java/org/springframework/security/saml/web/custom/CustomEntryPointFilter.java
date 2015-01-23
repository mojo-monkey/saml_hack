package org.springframework.security.saml.web.custom;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Controller;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@Qualifier(value = "customEntryPointFilter")
public class CustomEntryPointFilter extends GenericFilterBean
{
    @Autowired
    @Qualifier(value = "customSAMLContextProvider")
    protected SAMLContextProvider contextProvider;

    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl = FILTER_URL;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    public static final String FILTER_URL = "/saml/login";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);

        if (!processFilter(fi.getRequest())) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        try {
            initializeContext(fi.getRequest(), fi.getResponse(), null);
        } catch (MetadataProviderException e) {
            e.printStackTrace();
        }
    }

    public void initializeContext(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException, MetadataProviderException {
        SAMLMessageContext context = contextProvider.getLocalAndPeerEntity(request, response);
    }

    protected boolean processFilter(HttpServletRequest request) {
        return SAMLUtil.processFilter(filterProcessesUrl, request);
    }
}
