/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.sample.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class X509CertificateServlet extends HttpServlet {

    private static final long serialVersionUID = -7182121722709941646L;
    private static final Log log = LogFactory.getLog(X509CertificateServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws ServletException, IOException {
        String commonAuthURL = IdentityUtil.getServerURL(X509CertificateConstants.COMMON_AUTH, false, true);
        String param = servletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
        if (param == null) {
            throw new IllegalArgumentException(X509CertificateConstants.SESSION_DATA_KEY
                    + " parameter is null.");
        }
        Object object = servletRequest.getAttribute(X509CertificateConstants.X509Certificate);
        if (object != null) {
            X509Certificate[] certificates = (X509Certificate[]) object;
            if (certificates.length > 0) {
                X509Certificate certs[] = (X509Certificate[]) object;
                X509Certificate cert = certs[0];
                byte[] data = new byte[0];
                commonAuthURL += "?" + X509CertificateConstants.SESSION_DATA_KEY + "="
                        + URLEncoder.encode(param, X509CertificateConstants.UTF_8) + "&"
                        + X509CertificateConstants.X509_AUTH + "=" + cert.getSerialNumber() + "&"
                        + "data=" + data;
                try {
                    data = cert.getEncoded();
                } catch (CertificateEncodingException e) {
                    e.printStackTrace();
                }
                /**
                 * if admin request to create new user
                 */
                if (!StringUtils.isEmpty(servletRequest.getParameter("password")) && !StringUtils
                        .isEmpty(servletRequest.getParameter(X509CertificateConstants.USER_NAME))) {
                    AuthenticationAdminStub authenticationAdminStub = new AuthenticationAdminStub(null,
                            X509CertificateConstants.AUTHENTICATION_ADMIN);
                    try {
                        if (authenticationAdminStub.login("admin", servletRequest
                                .getParameter("password"), servletRequest.getRemoteUser())) {
                            X509CertificateUtil certificateBasedMultiFactorAuthenticationAdminService
                                    = new X509CertificateUtil();
                            if (certificateBasedMultiFactorAuthenticationAdminService.isEmpty(servletRequest.getParameter(X509CertificateConstants.USER_NAME))) {
                                if (certificateBasedMultiFactorAuthenticationAdminService
                                        .addCertificate(servletRequest.getParameter(X509CertificateConstants.USER_NAME), data)) {
                                    X509CertificateAssociation x509CertificateAssociation = new X509CertificateAssociation();
                                    if (StringUtils.isEmpty(servletRequest
                                            .getParameter(X509CertificateConstants.USER_NAME))) {
                                        x509CertificateAssociation.associateID(FrameworkConstants.LOCAL_IDP_NAME, String.valueOf(cert.getSerialNumber()), servletRequest.getParameter("username"));
                                    }
                                    servletResponse.sendRedirect(commonAuthURL);
                                }
                            }
                        }
                    } catch (Exception e) {
                        log.error(e.getStackTrace());
                    }
                } else {
                    /**
                     * directly check for user Authentication
                     */
                    servletResponse.sendRedirect(commonAuthURL);
                }
            } else {
                log.error("X509 Certificate object is null");
            }
        }
    }
}




