/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.authenticator.x509Certificate;

import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import static org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateUtil.DOMAIN_PATH_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateUtil.DOMAIN_PORT_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateUtil.PROTOCOL_DOMAIN_SEPARATOR;

/**
 * X509 Certificate Servlet.
 */
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
            commonAuthURL = ServiceURLBuilder.create().addPath(X509CertificateConstants.COMMON_AUTH).build()
                    .getAbsoluteInternalURL();
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL.", e);
        }

        String authenticationEndpoint = X509CertificateUtil.getX509Parameters().get(X509CertificateConstants
                .AUTHENTICATION_ENDPOINT_PARAMETER);

        if (authenticationEndpoint != null) {
            URL authenticationEndpointURL = new URL(authenticationEndpoint);
            String protocol = authenticationEndpointURL.getProtocol();
            String host = authenticationEndpointURL.getHost();
            int port = authenticationEndpointURL.getPort();
            if (port == -1) {
                commonAuthURL = protocol + PROTOCOL_DOMAIN_SEPARATOR + host + DOMAIN_PATH_SEPARATOR
                        + X509CertificateConstants.COMMON_AUTH;
            } else {
                commonAuthURL = protocol + PROTOCOL_DOMAIN_SEPARATOR + host + DOMAIN_PORT_SEPARATOR
                        + port + DOMAIN_PATH_SEPARATOR + X509CertificateConstants.COMMON_AUTH;
            }
        }

        String param = servletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
        if (param == null) {
            throw new IllegalArgumentException(X509CertificateConstants.SESSION_DATA_KEY
                    + " parameter is null.");
        } else {
            commonAuthURL += "?" + X509CertificateConstants.SESSION_DATA_KEY + "="
                    + URLEncoder.encode(param, X509CertificateConstants.UTF_8) + "&"
                    + X509CertificateConstants.SUCCESS + "=true";
            servletResponse.sendRedirect(commonAuthURL);
        }
    }
}