/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Authenticator of X509Certificate.
 */
public class X509CertificateAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {
    private static Log log = LogFactory.getLog(X509CertificateAuthenticator.class);

    /**
     * Initialize the process and call servlet .
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        try {
            if (authenticationContext.isRetrying()) {
                String errorPageUrl = IdentityUtil.getServerURL(X509CertificateConstants.ERROR_PAGE, false, false);
                String redirectUrl = errorPageUrl + ("?" + FrameworkConstants.SESSION_DATA_KEY + "="
                        + authenticationContext.getContextIdentifier()) + "&" + X509CertificateConstants.AUTHENTICATORS
                        + "=" + getName() + X509CertificateConstants.RETRY_PARAM_FOR_CHECKING_CERTIFICATE
                        + authenticationContext.getProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE);
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE, "");

                if (log.isDebugEnabled()) {
                    log.debug("Redirect to error page: " + redirectUrl);
                }
                httpServletResponse.sendRedirect(redirectUrl);
            } else {
                String authEndpoint = getAuthenticatorConfig().getParameterMap().
                        get(X509CertificateConstants.AUTHENTICATION_ENDPOINT_PARAMETER);
                if (StringUtils.isEmpty(authEndpoint)) {
                    authEndpoint = X509CertificateConstants.AUTHENTICATION_ENDPOINT;
                }
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                        authenticationContext.getQueryParams(), authenticationContext.getCallerSessionKey(),
                        authenticationContext.getContextIdentifier());
                if (log.isDebugEnabled()) {
                    log.debug("Request sent to " + authEndpoint);
                }
                httpServletResponse.sendRedirect(authEndpoint + ("?" + queryParams));
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while redirecting to the login page", e);
        }
    }

    /**
     * Validate the certificate.
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        Object object = httpServletRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE);
        if (object != null) {
            X509Certificate[] certificates;
            if (object instanceof X509Certificate[]) {
                certificates = (X509Certificate[]) object;
            } else {
                throw new AuthenticationFailedException("Exception while casting the X509Certificate");
            }
            if (certificates.length > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("X509 Certificate Checking in servlet is done! ");
                }
                X509Certificate cert = certificates[0];
                byte[] data;
                try {
                    data = cert.getEncoded();
                } catch (CertificateEncodingException e) {
                    throw new AuthenticationFailedException("Encoded certificate in not found", e);
                }
                String certAttributes = String.valueOf(cert.getSubjectX500Principal());
                Map<ClaimMapping, String> claims;
                claims = getSubjectAttributes(authenticationContext, certAttributes);
                AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
                String userName = (String) authenticationContext.getProperty
                        (X509CertificateConstants.X509_CERTIFICATE_USERNAME);
                if (!StringUtils.isEmpty(userName)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Getting X509Certificate username");
                    }
                    if (authenticatedUser != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated username is: " + authenticatedUser);
                        }
                        String authenticatedUserName = authenticatedUser.getAuthenticatedSubjectIdentifier();
                        if (authenticatedUserName.equals(userName)) {
                            addOrValidateCertificate(userName, authenticationContext, data, claims, cert);
                        } else {
                            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                                    X509CertificateConstants.USERNAME_CONFLICT);
                            throw new AuthenticationFailedException("Couldn't find X509 certificate to " +
                                    "this authenticated user: " + authenticatedUserName);
                        }
                    } else {
                        addOrValidateCertificate(userName, authenticationContext, data, claims, cert);
                    }
                } else {
                    authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                            X509CertificateConstants.USERNAME_NOT_FOUND_FOR_X509_CERTIFICATE_ATTRIBUTE);
                    throw new AuthenticationFailedException("Couldn't find the username for X509Certificate's " +
                            "attribute");
                }
            } else {
                throw new AuthenticationFailedException("X509Certificate object is null");
            }
        } else {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_FOUND_ERROR_CODE);
            throw new AuthenticationFailedException("Unable to find X509 Certificate in browser");
        }
    }

    /**
     * To add or validate the certificate against to the user name.
     *
     * @param userName              certificate's username
     * @param authenticationContext the authentication context
     * @param data                  certificate's data
     * @param claims                claims of the user
     * @param cert                  X509 certificate
     * @throws AuthenticationFailedException
     */
    private void addOrValidateCertificate(String userName, AuthenticationContext authenticationContext, byte[] data,
                                          Map<ClaimMapping, String> claims, X509Certificate cert) throws
            AuthenticationFailedException {

        boolean isUserCertValid;
        boolean isSelfRegistrationEnable = Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().
                get(X509CertificateConstants.ENFORCE_SELF_REGISTRATION));
        try {
            isUserCertValid = X509CertificateUtil.validateCerts(userName, authenticationContext, data,
                    isSelfRegistrationEnable);
        } catch (AuthenticationFailedException e) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_VALIDATED_ERROR_CODE);
            throw new AuthenticationFailedException("Error in validating the user certificate");
        }


        if(isUserCertValid) {
            allowUser(userName, claims, cert, authenticationContext);
        } else {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_VALID_ERROR_CODE);
            throw new AuthenticationFailedException("X509Certificate is not valid");
        }
    }

    /**
     * Check canHandle.
     *
     * @param httpServletRequest http request
     * @return boolean status
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return (httpServletRequest.getParameter(X509CertificateConstants.SUCCESS) != null);
    }

    /**
     * Get context identifier.
     *
     * @param httpServletRequest http request
     * @return authenticator contextIdentifier
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
    }

    /**
     * Get the authenticator name.
     *
     * @return authenticator name
     */
    public String getName() {
        return X509CertificateConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get authenticator friendly name.
     *
     * @return authenticator friendly name
     */
    public String getFriendlyName() {
        return X509CertificateConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get username.
     *
     * @param authenticationContext authentication context
     * @return username username
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

    /**
     * @param authenticationContext authentication context
     * @param certAttributes        principal attributes from certificate.
     * @return claim map
     * @throws AuthenticationFailedException
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(AuthenticationContext authenticationContext, String
            certAttributes)
            throws AuthenticationFailedException {
        Map<ClaimMapping, String> claims = new HashMap<>();
        LdapName ldapDN;
        try {
            ldapDN = new LdapName(certAttributes);
        } catch (InvalidNameException e) {
            throw new AuthenticationFailedException("error occurred while get the certificate claims", e);
        }
        if (log.isDebugEnabled()) {
                log.debug("Getting username attribute");
            }
        String userNameAttribute = getAuthenticatorConfig().getParameterMap().get(X509CertificateConstants.USERNAME);
        for (Rdn distinguishNames : ldapDN.getRdns()) {
            claims.put(ClaimMapping.build(distinguishNames.getType(), distinguishNames.getType(),
                    null, false), String.valueOf(distinguishNames.getValue()));
            if (StringUtils.isNotEmpty(userNameAttribute)) {
                if (userNameAttribute.equals(distinguishNames.getType())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Setting X509Certificate username attribute: " + userNameAttribute
                                + "and value is " + distinguishNames.getValue());
                    }
                    authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME, String
                            .valueOf(distinguishNames.getValue()));
                }
            }
        }
        return claims;
    }

    /**
     * Allow user login into system.
     *
     * @param userName              username of the user.
     * @param claims                claim map.
     * @param cert                  x509 certificate.
     * @param authenticationContext authentication context.
     */
    private void allowUser(String userName, Map claims, X509Certificate cert,
                           AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUserObj;
        authenticatedUserObj = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName);
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(String.valueOf(cert.getSerialNumber()));
        authenticatedUserObj.setUserAttributes(claims);
        authenticationContext.setSubject(authenticatedUserObj);
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled
     */
    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }
}