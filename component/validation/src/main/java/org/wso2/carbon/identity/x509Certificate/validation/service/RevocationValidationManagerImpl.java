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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
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

    private static final Log log = LogFactory.getLog(RevocationValidationManagerImpl.class);

    @Override
    public boolean verifyRevocationStatus(X509Certificate peerCertificate) throws CertificateValidationException {
        List<RevocationValidator> revocationValidators = CertificateValidationUtil.loadValidatorConfigFromRegistry();
        Collections.sort(revocationValidators, revocationValidatorComparator);
        int validatorCount = revocationValidators.size();

        for (RevocationValidator validator : revocationValidators) {
            --validatorCount;
            if (validator.isEnable()) {
                try {
                    return checkValidity(validator, peerCertificate);
                } catch (CertificateValidationException e) {
                    if(validatorCount > 0) {
                        continue;
                    } else {
                        throw e;
                    }
                }
            }
        }
        return false;
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

    private boolean checkValidity(RevocationValidator validator, X509Certificate certificate)
            throws CertificateValidationException {
        log.info("X509 Certificate validation with " + validator.getClass().getName());
        List<CACertificate> caCertificateList = CertificateValidationUtil.loadCaCertsFromRegistry(certificate);
        for(CACertificate caCertificate : caCertificateList) {
            RevocationStatus revocationStatus;
            try {
                revocationStatus = validator.checkRevocationStatus(certificate,
                        caCertificate.getX509Certificate(), validator.getRetryCount());
            } catch (CertificateValidationException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Error when validation certificate revocation with " + validator.getClass().getName() +
                            ". So check with the next CA certificate in the list.", e);
                }
                continue;
            }

            if(RevocationStatus.UNKNOWN.equals(revocationStatus)) {
                // indication that the OCSP Responder/CRL URls has no information about the requested certificate.
                if(log.isDebugEnabled()) {
                    log.debug("Error when validation certificate revocation with " + validator.getClass().getName() +
                            ". So check with the next CA certificate in the list.");
                }
                continue;
            } else if (RevocationStatus.REVOKED.equals(revocationStatus)) {
                return true;
            } else if(validator.isFullChainValidationEnable() && !caCertificate.getX509Certificate().getIssuerDN().equals
                    (caCertificate.getX509Certificate().getSubjectDN())) {
                checkValidity(validator, caCertificate.getX509Certificate());
            } else if(RevocationStatus.GOOD.equals(revocationStatus)) {
                return false;
            }
        }
        throw new CertificateValidationException("Cannot check revocation status of the certificate.");
    }

}
