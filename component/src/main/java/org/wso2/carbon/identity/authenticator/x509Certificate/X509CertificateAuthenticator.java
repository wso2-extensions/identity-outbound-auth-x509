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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Authenticator of X509Certificate.
 */
public class X509CertificateAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {
    private static Log log = LogFactory.getLog(X509CertificateAuthenticator.class);

    /**
     * Initialize the process and call servlet .
     *
     * @param httpServletRequest    http request.
     * @param httpServletResponse   http response.
     * @param authenticationContext authentication context.
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        String authEndpoint = null;
        try {
            authEndpoint = ServletURLUtils.getUserAuthEndpoint();
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(authenticationContext
                    .getQueryParams(), authenticationContext.getCallerSessionKey(), authenticationContext
                    .getContextIdentifier());
            httpServletResponse.sendRedirect(httpServletResponse.encodeRedirectURL(authEndpoint
                    + ("?" + queryParams)));
            if (log.isDebugEnabled()) {
                log.debug("Request send to " + authEndpoint);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error when sending to the login page :"
                    + authEndpoint, e);
        }
    }

    /**
     * Validate the certificate.
     *
     * @param httpServletRequest    http request.
     * @param httpServletResponse   http response.
     * @param authenticationContext authentication context.
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String userName = authenticatedUser.getAuthenticatedSubjectIdentifier();
        Object object = httpServletRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE);
        if (object != null) {
            X509Certificate[] certificates = (X509Certificate[]) object;
            if (certificates.length > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("X509 Certificate Checking in servlet is done! ");
                }
                X509Certificate certs[] = (X509Certificate[]) object;
                X509Certificate cert = certs[0];
                byte[] data;
                try {
                    data = cert.getEncoded();
                } catch (CertificateEncodingException e) {
                    throw new AuthenticationFailedException("Encoded certificate in not found", e);
                }
                X509CertificateUtil certificateUtil = new X509CertificateUtil();
                if (certificateUtil.isEmpty(userName)) {
                    certificateUtil.addCertificate(userName, data);
                    authenticationContext.setSubject(AuthenticatedUser
                            .createLocalAuthenticatedUserFromSubjectIdentifier(userName));
                } else {
                    if (certificateUtil.validateCerts(userName, data)) {
                        authenticationContext.setSubject(AuthenticatedUser
                                .createLocalAuthenticatedUserFromSubjectIdentifier(userName));
                    } else {
                        throw new AuthenticationFailedException("X509Certificate is not valid");
                    }
                }
            } else {
                throw new AuthenticationFailedException("X509Certificate object is null");
            }
        } else {
            throw new AuthenticationFailedException("X509Certificate not found");
        }
    }

    /**
     * Check canHandle.
     *
     * @param httpServletRequest http request
     * @return boolean status
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY) != null;
    }

    /**
     * Get context identifier.
     *
     * @param httpServletRequest http request.
     * @return authenticator contextIdentifier.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
    }

    /**
     * Get the authenticator name.
     *
     * @return authenticator name.
     */
    public String getName() {
        return X509CertificateConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get authenticator friendly name.
     *
     * @return authenticator friendly name.
     */
    public String getFriendlyName() {
        return X509CertificateConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get username.
     *
     * @param authenticationContext authentication context.
     * @return username username.
     */
    private AuthenticatedUser getUsername(AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= authenticationContext.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = authenticationContext.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }
}