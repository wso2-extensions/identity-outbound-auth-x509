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

import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

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
        String commonAuthURL = IdentityUtil
                .getServerURL(X509CertificateConstants.COMMON_AUTH, false, true);
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