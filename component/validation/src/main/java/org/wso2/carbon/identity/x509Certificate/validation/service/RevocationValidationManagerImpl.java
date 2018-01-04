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

package org.wso2.carbon.identity.x509Certificate.validation.service;

import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Manager class responsible for validating client certificates. This class will invoke the available validators
 * based on the configured priorities.
 */
public class RevocationValidationManagerImpl implements RevocationValidationManager {

    @Override
    public boolean verifyRevocationStatus(X509Certificate peerCertificate) throws CertificateValidationException {
        List<RevocationValidator> revocationValidators = CertificateValidationUtil.loadValidatorConfig();
        Collections.sort(revocationValidators, revocationValidatorComparator);
        boolean isRevoked = false;

        for (RevocationValidator validator : revocationValidators) {
            if (validator.isEnable()) {
                RevocationStatus revocationStatus = validator.checkRevocationStatus(peerCertificate, null);
                if (RevocationStatus.REVOKED.equals(revocationStatus)) {
                    isRevoked = true;
                }
            }
        }
        return isRevoked;
    }

    private static Comparator<RevocationValidator> revocationValidatorComparator = new Comparator<RevocationValidator>() {

        @Override
        public int compare(RevocationValidator revocationValidator1,
                           RevocationValidator revocationValidator2) {
            if (revocationValidator1.getPriority() > revocationValidator2.getPriority()) {
                return 1;
            } else if (revocationValidator1.getPriority() < revocationValidator2.getPriority()) {
                return -1;
            } else {
                return 0;
            }
        }
    };

}
