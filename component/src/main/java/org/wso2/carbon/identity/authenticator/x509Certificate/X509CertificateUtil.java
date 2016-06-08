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

import org.apache.axiom.om.util.Base64;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import javax.security.cert.X509Certificate;

/**
 * Working with certificate and claims store.
 *
 * @since 1.0.0
 */
public class X509CertificateUtil extends AbstractAdmin {

    /**
     * Get certificate from claims.
     *
     * @param userName name of the user.
     * @return x509 certificate.
     * @throws AuthenticationFailedException authentication failed exception.
     */
    private static X509Certificate getCertificate(String userName)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        UserStoreManager userStoreManager;
        RealmService realmService = X509CertificateRealmServiceComponent.getRealmService();
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        try {
            if (userName.contains(X509CertificateConstants.AT_SIGN)) {
                tenantID = realmService.getTenantManager().getTenantId(userName
                        .substring(userName.lastIndexOf(X509CertificateConstants.AT_SIGN) + 1));
            }
            userStoreManager = realmService.getTenantUserRealm(tenantID).getUserStoreManager();
            String certificate;
            if (userStoreManager.getUserClaimValue(userName, X509CertificateConstants.USER_CERTIFICATE,
                    X509CertificateConstants.DEFAULT) != null) {
                certificate = userStoreManager.getUserClaimValue(userName, X509CertificateConstants
                        .USER_CERTIFICATE, X509CertificateConstants.DEFAULT);
            } else {
                return null;
            }
            x509Certificate = X509Certificate.getInstance(Base64.decode(certificate));
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
     * @param userName         name of the user.
     * @param certificateBytes x509 certificate.
     * @return boolean status of the action.
     * @throws AuthenticationFailedException authentication failed exception.
     */
    public synchronized boolean addCertificate(String userName, byte[] certificateBytes)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);
            org.wso2.carbon.user.core.UserStoreManager userStoreManager = getUserRealm()
                    .getUserStoreManager();
            userStoreManager.setUserClaimValue(userName, X509CertificateConstants.USER_CERTIFICATE,
                    Base64.encode(x509Certificate.getEncoded()), X509CertificateConstants.DEFAULT);
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while set certificate ", e);
        }
        return true;
    }

    /**
     * Validate the certificate against with given certificate.
     *
     * @param userName         name of the user.
     * @param certificateBytes x509 certificate.
     * @return boolean status of the action.
     * @throws AuthenticationFailedException
     */
    public synchronized boolean validateCerts(String userName, byte[] certificateBytes)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        }
        return x509Certificate.equals(getCertificate(userName));
    }

    /**
     * Check availability of certificate.
     *
     * @param userName name of the user.
     * @return boolean status of availability.
     */
    public synchronized boolean isEmpty(String userName) throws AuthenticationFailedException {
        return getCertificate(userName) == null;
    }
}