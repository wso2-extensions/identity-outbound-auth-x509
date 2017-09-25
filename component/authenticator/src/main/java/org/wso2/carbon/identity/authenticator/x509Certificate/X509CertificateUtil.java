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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.apache.commons.lang.StringUtils;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Working with certificate and claims store.
 */
public class X509CertificateUtil {
    private static Log log = LogFactory.getLog(X509CertificateUtil.class);

    /**
     * Get certificate from claims.
     *
     * @param username name of the user
     * @return x509 certificate
     * @throws AuthenticationFailedException authentication failed exception
     */
    public static X509Certificate getCertificate(String username) throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        UserRealm userRealm = getUserRealm(username);
        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            String claimURI = getClaimUri();
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername, new String[]{claimURI}, null);
                String userCertificate = userClaimValues.get(claimURI);
                if (log.isDebugEnabled()) {
                    log.debug("The user certificate is " + userCertificate);
                }
                if (StringUtils.isNotEmpty(userCertificate)) {
                    x509Certificate = X509Certificate.getInstance(Base64.decode(userCertificate));
                } else {
                    return null;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("UserRealm is null for username: " + username);
                }
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant domain : " +
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while decoding the certificate ", e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("Error while user manager for tenant id ", e);
        }
        return x509Certificate;
    }

    /**
     * Add certificate into claims.
     *
     * @param username         name of the user
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException authentication failed exception
     */
    public static synchronized boolean addCertificate(String username, byte[] certificateBytes)
            throws AuthenticationFailedException {
        Map<String, String> claims = new HashMap<>();
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm != null) {
                X509Certificate x509Certificate = X509Certificate.getInstance(certificateBytes);
                claims.put(getClaimUri(), Base64.encode(x509Certificate.getEncoded()));
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims,
                        X509CertificateConstants.DEFAULT);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("UserRealm is null for username: " + username);
                }
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant domain : " +
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate of user: " + username, e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while setting certificate of user: " + username, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("Error while user manager for tenant id", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("X509 certificate is added for user: " + username);
        }
        return true;
    }

    /**
     * Validate the certificate against with given certificate.
     *
     * @param userName         name of the user
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException
     */
    public static synchronized boolean validateCerts(String userName, byte[] certificateBytes)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("X509 certificate validation is completed. Result is " +
                    x509Certificate.equals(getCertificate(userName)));
        }
        return x509Certificate.equals(getCertificate(userName));
    }

    /**
     * Check availability of certificate.
     *
     * @param userName name of the user
     * @return boolean status of availability
     */
    public static synchronized boolean isCertificateExist(String userName) throws AuthenticationFailedException {
        return getCertificate(userName) != null;
    }

    /**
     * Get parameter values from local file.
     */
    public static Map<String, String> getX509Parameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(X509CertificateConstants.AUTHENTICATOR_NAME);
        if (authConfig != null) {
            return authConfig.getParameterMap();
        }
        if (log.isDebugEnabled()) {
            log.debug("AuthenticatorConfig is not provided for " + X509CertificateConstants.AUTHENTICATOR_NAME);
        }
        return Collections.emptyMap();
    }

    /**
     * Get user claimURI value.
     *
     * @return claimURI
     */
    public static String getClaimUri() {
        String claimURI = X509CertificateConstants.CLAIM_DIALECT_URI;
        Map<String, String> parametersMap = getX509Parameters();
        if (parametersMap != null) {
            Object claimURIObj = parametersMap.get(X509CertificateConstants.CLAIM_URI);
            if (claimURIObj != null) {
                claimURI = String.valueOf(claimURIObj);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("The X509Certificate claimUri is " + claimURI);
        }
        return claimURI;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param username the username
     * @return the userRealm for given username
     * @throws AuthenticationFailedException
     */
    public static UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        UserRealm userRealm = null;
        if (log.isDebugEnabled()) {
            log.debug("Getting userRealm for user: " + username);
        }
        try {
            if (StringUtils.isNotEmpty(username)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = X509CertificateRealmServiceComponent.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm for the username: " + username, e);
        }
        return userRealm;
    }
}