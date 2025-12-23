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

import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Singleton class to hold HTTP Service
 */
public class X509CertificateDataHolder {

    private static volatile X509CertificateDataHolder dataHolder = null;
    private AccountLockService accountLockService;
    private RealmService realmService;

    private X509CertificateDataHolder() {
    }

    /**
     * Get data holder instance.
     *
     * @return data holder instance
     */
    public static X509CertificateDataHolder getInstance() {
        if (dataHolder == null) {
            synchronized (X509CertificateDataHolder.class) {
                if (dataHolder == null) {
                    dataHolder = new X509CertificateDataHolder();
                }
            }
        }
        return dataHolder;
    }

    /**
     * Set account lock service.
     *
     * @return account lock service
     */
    public AccountLockService getAccountLockService() {

        if (accountLockService == null) {
            throw new RuntimeException("Account lock service has not been set.");
        }
        return accountLockService;
    }

    /**
     * Get account lock service.
     *
     * @param accountLockService
     */
    public void setAccountLockService(AccountLockService accountLockService) {

        this.accountLockService = accountLockService;
    }

    /***
     * Get realm service.
     *
     * @return RealmService
     */
    public RealmService getRealmService() {

        if (realmService == null) {
            throw new RuntimeException("Realm service has not been set.");
        }
        return realmService;
    }

    /**
     * Set realm service.
     *
     * @param realmService realm service to be set.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
