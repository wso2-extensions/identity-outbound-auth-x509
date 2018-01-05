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

package org.wso2.carbon.identity.x509Certificate.validation.validator;

import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;

import java.security.cert.X509Certificate;

/**
 * All the revocation validators should implement this interface.
 */
public interface RevocationValidator {

    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert)
            throws CertificateValidationException;

    public boolean isEnable();

    public void setEnable(boolean enabled);

    public int getPriority();

    public void setPriority(int priority);
}
