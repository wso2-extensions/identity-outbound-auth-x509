/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.x509Certificate.validation.model;

import java.security.cert.X509Certificate;
import java.util.List;

public class CACertificate {

    private List<String> crlUrls;
    private List<String> ocspUrls;
    private X509Certificate x509Certificate;

    public CACertificate() {

    }

    public CACertificate(List<String> crlUrls, List<String> ocspUrls, X509Certificate x509Certificate) {
        this.crlUrls = crlUrls;
        this.ocspUrls = ocspUrls;
        this.x509Certificate = x509Certificate;
    }

    public List<String> getCrlUrl() {
        return crlUrls;
    }

    public void setCrlUrl(List<String> crlUrls) {
        this.crlUrls = crlUrls;
    }

    public List<String> getOcspUrl() {
        return ocspUrls;
    }

    public void setOcspUrl(List<String> ocspUrls) {
        this.ocspUrls = ocspUrls;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }
}
