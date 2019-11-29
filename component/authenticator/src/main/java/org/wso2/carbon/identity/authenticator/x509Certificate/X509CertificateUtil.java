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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManager;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManagerImpl;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Working with certificate and claims store.
 */
public class X509CertificateUtil {
    private static final Log log = LogFactory.getLog(X509CertificateUtil.class);

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
                    CertificateFactory cf = CertificateFactory.getInstance("X509");
                    x509Certificate = (X509Certificate) cf.generateCertificate
                            (new ByteArrayInputStream(Base64.decode(userCertificate)));
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
        } catch (CertificateException e) {
            throw new AuthenticationFailedException("Error while decoding the certificate ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while retrieving the user store manager ", e);
        }
        return x509Certificate;
    }

    /**
     * Add certificate into claims.
     *
     * @param username        name of the user
     * @param x509Certificate x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException authentication failed exception
     */
    public static boolean addCertificate(String username, X509Certificate x509Certificate)
            throws AuthenticationFailedException {
        Map<String, String> claims = new HashMap<>();
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm != null) {
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
            throw new AuthenticationFailedException("Error while retrieving the user store manager ", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("X509 certificate is added for user: " + username);
        }
        return true;
    }

    /**
     * Validate the user certificate
     *
     * @param userName         name of the user
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException
     */
    public static boolean validateCertificate(String userName, AuthenticationContext authenticationContext,
                                              byte[] certificateBytes, boolean isSelfRegistrationEnable)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));

            if (isSelfRegistrationEnable && isCertificateExist(userName) && !isUserCertificateValid(userName,
                    x509Certificate)) {
                return false;
            } else if (!isSelfRegistrationEnable && !isUserExists(userName, authenticationContext)) {
                return false;
            }

            if (isCertificateRevoked(x509Certificate)) {
                if (log.isDebugEnabled()) {
                    log.debug("X509 certificate with serial num: " + x509Certificate.getSerialNumber() +
                            " is revoked");
                }
                if (isSelfRegistrationEnable) {
                    deleteUserCertificate(userName, x509Certificate);
                }
                return false;
            } else if (isSelfRegistrationEnable && !isCertificateExist(userName)) {
                addUserCertificate(userName, x509Certificate);
            }
        } catch (CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        } catch (CertificateValidationException e) {
            throw new AuthenticationFailedException("Error while validating client certificate with serial num: ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm for the username: " + userName, e);
        }
        return true;
    }

    /**
     * Check availability of certificate.
     *
     * @param userName name of the user
     * @return boolean status of availability
     */
    public static boolean isCertificateExist(String userName) throws AuthenticationFailedException {
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
     * Get X509Certificate claimURI value.
     *
     * @return X509Certificate claimURI
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
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm for the username: " + username, e);
        }
        return userRealm;
    }

    /**
     * Check the revocation status of the certificate
     *
     * @param x509Certificate x509 certificate
     * @return true if the certificate is revoked
     * @throws CertificateValidationException
     */
    private static boolean isCertificateRevoked(X509Certificate x509Certificate) throws CertificateValidationException {

        RevocationValidationManager revocationValidationManager = new RevocationValidationManagerImpl();
        return revocationValidationManager.verifyRevocationStatus(x509Certificate);
    }

    private static void deleteUserCertificate(String userName, X509Certificate x509Certificate)
            throws AuthenticationFailedException {

        if (isCertificateExist(userName) && isUserCertificateValid(userName, x509Certificate)) {
            if (log.isDebugEnabled()) {
                log.debug("Provided X509 client certificate with serial num: " + x509Certificate.getSerialNumber() +
                        " has been revoked. Removing the x509Certificate claim of the user: " + userName);
            }
            deleteCertificate(userName);
        }
    }

    private static void deleteCertificate(String username) throws AuthenticationFailedException {

        String[] claims = new String[1];
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm != null) {
                claims[0] = getClaimUri();
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                userRealm.getUserStoreManager().deleteUserClaimValues(tenantAwareUsername, claims,
                        X509CertificateConstants.DEFAULT);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("UserRealm is null for username: " + username);
                }
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant domain : " +
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while deleting certificate of user: " + username, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("X509 certificate is deleted for user: " + username);
        }
    }

    private static void addUserCertificate(String userName, X509Certificate x509Certificate)
            throws AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("X509 Certificate with serial num: " + x509Certificate.getSerialNumber() +
                    " does not exit for user: " + userName);
        }
        X509CertificateUtil.addCertificate(userName, x509Certificate);
        if (log.isDebugEnabled()) {
            log.debug("Adding the X509 certificate with serial num: " + x509Certificate.getSerialNumber() +
                    " as a user claim.");
        }
    }

    private static boolean isUserCertificateValid(String userName, X509Certificate x509Certificate)
            throws AuthenticationFailedException {

        X509Certificate certInUserClaim = getCertificate(userName);
        if (log.isDebugEnabled()) {
            log.debug("X509 certificate with serial num: " + x509Certificate.getSerialNumber() +
                    " is getting matched with the user certificate with serial num : " +
                    certInUserClaim.getSerialNumber() + " in the user claim of user: " + userName);
        }
        return x509Certificate.equals(certInUserClaim);
    }

    private static boolean isUserExists(String userName, AuthenticationContext authenticationContext)
            throws UserStoreException, AuthenticationFailedException {

        if (Boolean.valueOf(getX509Parameters().get(X509CertificateConstants.SEARCH_ALL_USERSTORES))) {
            String[] filteredUsers = X509CertificateUtil.getUserRealm(userName).getUserStoreManager().listUsers
                    (MultitenantUtils.getTenantAwareUsername(userName), X509CertificateConstants.MAX_ITEM_LIMIT_UNLIMITED);
            if (filteredUsers.length == 1) {
                if (log.isDebugEnabled()) {
                    log.debug("User exists with the user name: " + userName);
                }
                return true;
            } else if (filteredUsers.length > 1) {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USERNAME_CONFLICT);
                throw new AuthenticationFailedException("Conflicting users with user name: " + userName);
            } else if (getX509Parameters().containsKey(X509CertificateConstants.LOGIN_CLAIM_URIS)) {
                for (String multiAttributeClaimUri : getX509Parameters()
                        .get(X509CertificateConstants.LOGIN_CLAIM_URIS).split(",")) {
                    String[] usersWithClaim = ((AbstractUserStoreManager) X509CertificateUtil.getUserRealm(userName)
                            .getUserStoreManager()).getUserList(multiAttributeClaimUri, userName, null);
                    if (usersWithClaim.length == 1) {
                        return true;
                    } else if (usersWithClaim.length > 1) {
                        authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                                X509CertificateConstants.USERNAME_CONFLICT);
                        throw new AuthenticationFailedException("Conflicting users with claim value: " + userName);
                    }
                }
                throw new AuthenticationFailedException("Unable to find X509 Certificate's user in user store. ");
            } else {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USER_NOT_FOUND);
                throw new AuthenticationFailedException("Unable to find X509 Certificate's user in user store. ");
            }
        } else {
            boolean isUserExist = X509CertificateUtil.getUserRealm(userName).getUserStoreManager().isExistingUser
                    (MultitenantUtils.getTenantAwareUsername(userName));
            if (isUserExist) {
                if (log.isDebugEnabled()) {
                    log.debug("User exists with the user name: " + userName);
                }
                return true;
            } else {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USER_NOT_FOUND);
                throw new AuthenticationFailedException(" Unable to find X509 Certificate's user in user store. ");
            }
        }
    }

}