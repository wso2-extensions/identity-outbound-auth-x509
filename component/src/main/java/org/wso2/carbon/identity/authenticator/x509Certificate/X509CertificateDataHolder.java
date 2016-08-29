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

import org.osgi.service.http.HttpService;

/**
 * Singleton class to hold HTTP Service
 */
public class X509CertificateDataHolder {

    private static volatile X509CertificateDataHolder dataHolder = null;
    private HttpService httpService;

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
     * Get http service.
     *
     * @return http service
     */
    public HttpService getHttpService() {
        return httpService;
    }

    /**
     * Set http service.
     *
     * @return http service
     */
    public void setHttpService(HttpService httpService) {
        this.httpService = httpService;
    }
}