/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.x509Certificate;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.net.URLEncoder;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * X509 Certificate Servlet.
 */
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=" + X509CertificateConstants.SERVLET_URL,
                "osgi.http.whiteboard.servlet.name=X509CertificateServlet",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class X509CertificateServlet extends HttpServlet {

    private static final long serialVersionUID = -7182121722709941646L;

    /**
     * Servlet doGet.
     *
     * @param servletRequest  servlet request
     * @param servletResponse servlet response
     * @throws ServletException servlet failed exception
     * @throws IOException      IO failed exception
     */
    @Override
    protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws ServletException, IOException {
        doPost(servletRequest, servletResponse);
    }

    /**
     * Servlet doPost.
     *
     * @param servletRequest  servlet request
     * @param servletResponse servlet response
     * @throws ServletException servlet failed exception
     * @throws IOException      IO failed exception
     */
    @Override
    protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws ServletException, IOException {

        String commonAuthURL;
        try {
            // Check if internal hostname should be used for redirect.
            boolean useInternalHostname = Boolean.parseBoolean(IdentityUtil.getProperty(
                    X509CertificateConstants.USE_INTERNAL_HOSTNAME_FOR_REDIRECT));

            if (useInternalHostname) {
                commonAuthURL = ServiceURLBuilder.create().addPath(X509CertificateConstants.COMMON_AUTH).build()
                        .getAbsoluteInternalURL();
            } else {
                commonAuthURL = ServiceURLBuilder.create().addPath(X509CertificateConstants.COMMON_AUTH).build()
                        .getAbsolutePublicURL();
            }
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL.", e);
        }

        String param = servletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
        if (param == null) {
            throw new IllegalArgumentException(X509CertificateConstants.SESSION_DATA_KEY
                    + " parameter is null.");
        } else {
            AuthenticationContext authenticationContext = FrameworkUtils.getContextData(servletRequest);
            try {
                if (authenticationContext != null) {
                    authenticationContext.setProperty(X509CertificateConstants.X_509_CERTIFICATE,
                            servletRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE));
                }
                commonAuthURL += "?" + X509CertificateConstants.SESSION_DATA_KEY + "="
                        + URLEncoder.encode(param, X509CertificateConstants.UTF_8) + "&"
                        + X509CertificateConstants.SUCCESS + "=true";
                servletResponse.sendRedirect(commonAuthURL);
            } finally {
                if (authenticationContext != null) {
                    FrameworkUtils.addAuthenticationContextToCache(
                            authenticationContext.getContextIdentifier(), authenticationContext);
                }
            }
        }
    }
}
