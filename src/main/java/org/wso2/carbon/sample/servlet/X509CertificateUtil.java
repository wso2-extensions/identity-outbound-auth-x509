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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import javax.security.cert.X509Certificate;

/**
 *
 */
public class X509CertificateUtil extends AbstractAdmin {
    private static final Log log = LogFactory.getLog(X509CertificateUtil.class);

    /**
     * @param username
     * @param certificateByte
     * @return
     * @throws Exception
     */
    public synchronized boolean addCertificate(String username, byte[] certificateByte)
            throws Exception {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateByte);
        } catch (javax.security.cert.CertificateException e) {
            String msg = "Error while retrieving certificate ";
            log.error(msg, e);
            throw new Exception(msg, e);
        }
        org.wso2.carbon.user.core.UserStoreManager manager = getUserRealm().getUserStoreManager();
        manager.setUserClaimValue(username, X509CertificateConstants.USER_CERTIFICATE,
                Base64.encode(x509Certificate.getEncoded()), X509CertificateConstants.DEFAULT);
        return true;
    }

    /**
     * @param userName
     * @param certificateBytes
     * @return
     * @throws Exception
     */
    public synchronized boolean validateCerts(String userName, byte[] certificateBytes) throws Exception {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);
        } catch (javax.security.cert.CertificateException e) {
            String msg = "Error while retrieving certificate ";
            log.error(msg, e);
            throw new Exception(msg, e);
        }
        return x509Certificate.equals(getCertificate(userName));
    }

    /**
     * @param username
     * @return
     */
    public synchronized boolean isEmpty(String username) {
        try {
            return getCertificate(username) == null;
        } catch (Exception e) {
            log.error(e.getStackTrace());
            return false;
        }
    }

    /**
     * @param username
     * @return
     * @throws Exception
     */
    private static X509Certificate getCertificate(String username) throws Exception {
        X509Certificate x509Certificate;
        UserStoreManager manager;
        RealmService realmService = X509CertificateRealmServiceComponent.getRealmService();
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        try {
            if (username.contains("@")) {
                tenantID = realmService.getTenantManager().getTenantId(username.substring(username.lastIndexOf("@") + 1));
            }
            manager = realmService.getTenantUserRealm(tenantID).getUserStoreManager();
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String msg = "Error while user manager for tenant id " + tenantID;
            log.error(msg, e);
            throw new Exception(msg, e);
        }
        try {
            String cert;
            if (manager.getUserClaimValue(username, X509CertificateConstants.USER_CERTIFICATE,
                    X509CertificateConstants.DEFAULT) != null) {
                cert = manager.getUserClaimValue(username, X509CertificateConstants.USER_CERTIFICATE,
                        X509CertificateConstants.DEFAULT);
            } else {
                return null;
            }
            try {
                x509Certificate = X509Certificate.getInstance(Base64.decode(cert));
            } catch (javax.security.cert.CertificateException e) {
                String msg = "Error while decoding the certificate ";
                log.error(msg, e);
                throw new Exception(msg, e);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String msg = "Error while getting the certificate ";
            log.error(msg, e);
            throw new Exception(msg, e);
        }
        return x509Certificate;
    }
}
