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

package org.wso2.carbon.sample.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

/**
 * Authenticator of X509Certificate
 */
public class X509CertificateAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {
    private static Log log = LogFactory.getLog(X509CertificateAuthenticator.class);

    /**
     * @param request
     * @param httpServletResponse
     * @param authenticationContext
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        String X509_URL = null;
        String clefLoginPage = X509CertificateConstants.AUTH_ENDPOINT;
        String queryParams = FrameworkUtils
                .getQueryStringWithFrameworkContextId(authenticationContext.getQueryParams(),
                        authenticationContext.getCallerSessionKey(), authenticationContext
                                .getContextIdentifier());
        try {
            X509_URL = X509CertificateConstants.AUTH_ENDPOINT + X509CertificateConstants.SESSION_DATA_KEY + "="
                    + URLEncoder.encode(authenticationContext.getContextIdentifier()
                    , X509CertificateConstants.UTF_8);
            httpServletResponse.sendRedirect(httpServletResponse.encodeRedirectURL(clefLoginPage
                    + ("?" + queryParams + "&" + OIDCAuthenticatorConstants.CLIENT_ID + "="
                    + authenticationContext.getAuthenticatorProperties().get(OIDCAuthenticatorConstants
                    .CLIENT_ID))));
            if (log.isDebugEnabled()) {
                log.debug("Request send to " + clefLoginPage);
            }
//            response.sendRedirect(response.encodeRedirectURL(X509_URL));
        } catch (IOException e) {
            log.error("Error when sending to the login page :" + X509_URL, e);
            throw new AuthenticationFailedException("Authentication failed");
        }
    }


    /**
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String userID = request.getParameter(X509CertificateConstants.X509_AUTH);
        X509CertificateAssociation x509CertificateAssociation = new X509CertificateAssociation();
        String userName;
        try {
            userName = x509CertificateAssociation.getAssociatedUsername(context, userID);
//            X509CertificateUtil certificateBasedMultiFactorAuthenticationAdminService
//                    = new X509CertificateUtil();
//            if (!certificateBasedMultiFactorAuthenticationAdminService.isEmpty(userName)) {
//                if (certificateBasedMultiFactorAuthenticationAdminService.validateCerts(userName, httpServletRequest.getParameter("data"))) {
            context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName));
//                }
//            }
        } catch (UserProfileException e) {
            log.error(e.getStackTrace());
        }

    }

    /**
     * @param httpServletRequest
     * @return
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.X509_AUTH) != null;
    }

    /**
     * @param httpServletRequest
     * @return
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
    }

    /**
     * @return
     */
    public String getName() {
        return X509CertificateConstants.AUTHENTICATOR_NAME;
    }

    /**
     * @return
     */
    public String getFriendlyName() {
        return X509CertificateConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

}