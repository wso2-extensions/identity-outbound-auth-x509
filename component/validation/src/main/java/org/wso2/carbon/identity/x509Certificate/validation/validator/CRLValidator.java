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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;
import org.wso2.carbon.identity.x509Certificate.validation.cache.CRLCache;
import org.wso2.carbon.identity.x509Certificate.validation.cache.CRLCacheEntry;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * This is used to verify a certificate is revoked or not by using the Certificate Revocation List published
 * by the CA.
 */
public class CRLValidator implements RevocationValidator {

    private static final Log log = LogFactory.getLog(CRLValidator.class);
    private int priority;
    private boolean enabled;
    private int retryCount;
    private boolean fullChainValidationEnabled;

    public CRLValidator() {
    }

    /**
     * Checks revocation status (Good, Revoked) of the peer certificate. IssuerCertificate can be used
     * to check if the CRL URL has the Issuers Domain name. But this is not implemented at the moment.
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of the peer. not used currently.
     * @return revocation status of the peer certificate.
     * @throws org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException
     */
    @Override
    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert, int retryCount)
            throws CertificateValidationException {

        List<String> crlUrls = CertificateValidationUtil.getCrlDistributionPoints(peerCert);

        //check with distributions points in the list one by one. if one fails go to the other.
        for (String crlUrl : crlUrls) {
            log.info("Trying to get CRL for URL: " + crlUrl);

            X509CRL x509CRL = null;
            CRLCacheEntry crlCacheValue = CRLCache.getInstance().getValueFromCache(crlUrl);
            if (crlCacheValue != null) {
                x509CRL = crlCacheValue.getX509CRL();
            }
            Date currentDate = new Date();
            try {
                if (x509CRL != null) {
                    if (x509CRL.getNextUpdate() != null && currentDate.after(x509CRL.getNextUpdate())) {
                        log.error("CRL is too old.");
                        CRLCache.getInstance().clearCacheEntry(crlUrl);
                    } else {
                        RevocationStatus status = getRevocationStatus(x509CRL, peerCert);
                        log.info("CRL taken from cache.");
                        return status;
                    }
                }

                x509CRL = downloadCRLFromWeb(crlUrl, retryCount);
                if (x509CRL != null) {
                    CRLCacheEntry crlCacheEntry = new CRLCacheEntry();
                    crlCacheEntry.setX509CRL(x509CRL);
                    CRLCache.getInstance().addToCache(crlUrl, crlCacheEntry);
                    return getRevocationStatus(x509CRL, peerCert);
                }
            } catch (Exception e) {
                log.info("Either url is bad or cant build X509CRL. So check with the next url in the list.", e);
            }
        }
        throw new CertificateValidationException("Cannot check revocation status with the certificate");
    }

    @Override
    public boolean isEnable() {
        return enabled;
    }

    @Override
    public void setEnable(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public void setPriority(int priority) {
        this.priority = priority;
    }

    @Override
    public boolean isFullChainValidationEnable() {
        return fullChainValidationEnabled;
    }

    @Override
    public void setFullChainValidation(boolean fullChainValidationEnabled) {
        this.fullChainValidationEnabled = fullChainValidationEnabled;
    }

    @Override
    public int getRetryCount() {
        return retryCount;
    }

    @Override
    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }

    /**
     * Downloads CRL from the crlUrl. Does not support HTTPS
     */
    private static X509CRL downloadCRLFromWeb(String crlURL, int retryCount)
            throws IOException, CertificateValidationException {
        InputStream crlStream = null;
        X509CRL x509CRL = null;
        try {
            URL url = new URL(crlURL);
            crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            x509CRL = (X509CRL) cf.generateCRL(crlStream);
        } catch (MalformedURLException e) {
            throw new CertificateValidationException("CRL Url is malformed", e);
        } catch (IOException e) {
            if(retryCount == 0) {
                throw new CertificateValidationException("Cant reach URI: " + crlURL + " - only support HTTP", e);
            } else {
                log.info("Cant reach URI: " + crlURL + ". Retrying to connect - attempt " + retryCount);
                downloadCRLFromWeb(crlURL, --retryCount);
            }
        } catch (CertificateException e) {
            throw new CertificateValidationException(e);
        } catch (CRLException e) {
            throw new CertificateValidationException("Cannot generate X509CRL from the stream data", e);
        } finally {
            if (crlStream != null)
                crlStream.close();
        }
        return x509CRL;
    }

    private static RevocationStatus getRevocationStatus(X509CRL x509CRL, X509Certificate peerCert) {
        if (x509CRL.isRevoked(peerCert)) {
            return RevocationStatus.REVOKED;
        } else {
            return RevocationStatus.GOOD;
        }
    }

}
