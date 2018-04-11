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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This is used to verify a certificate is revoked or not by using the Online Certificate Status Protocol published
 * by the CA.
 */
public class OCSPValidator implements RevocationValidator {

    private static final Log log = LogFactory.getLog(OCSPValidator.class);
    private int priority;
    private boolean enabled;
    private int retryCount;
    private boolean fullChainValidationEnabled;
    private static final String BC = "BC";

    public OCSPValidator() {
    }

    @Override
    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert, int retryCount)
            throws CertificateValidationException {

        if(issuerCert == null) {
            throw new CertificateValidationException("Issuer Certificate is not available for OCSP validation");
        }

        OCSPReq request = generateOCSPRequest(issuerCert, peerCert.getSerialNumber());

        //This list will sometimes have non ocsp urls as well.
        List<String> locations = CertificateValidationUtil.getAIALocations(peerCert);

        if(CollectionUtils.isNotEmpty(locations)) {
            for (String serviceUrl : locations) {

                SingleResp[] responses;
                try {
                    OCSPResp ocspResponse = getOCSPResponce(serviceUrl, request, retryCount);
                    if (OCSPResponseStatus.SUCCESSFUL != ocspResponse.getStatus()) {
                        continue; // Server didn't give the response right.
                    }

                    BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                    responses = (basicResponse == null) ? null : basicResponse.getResponses();
                    //todo use the super exception
                } catch (Exception e) {
                    continue;
                }

                if (responses != null && responses.length == 1) {
                    SingleResp resp = responses[0];
                    RevocationStatus status = getRevocationStatus(resp);
                    return status;
                }
            }
        }
        throw new CertificateValidationException("Cant get Revocation Status from OCSP.");
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
     * This method generates an OCSP Request to be sent to an OCSP endpoint.
     *
     * @param issuerCert   is the Certificate of the Issuer of the peer certificate we are interested in.
     * @param serialNumber of the peer certificate.
     * @return generated OCSP request.
     * @throws CertificateValidationException
     *
     */
    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws CertificateValidationException {

        //TODO: Have to check if this is OK with synapse implementation.
        //Add provider BC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {

            byte[] issuerCertEnc = issuerCert.getEncoded();
            X509CertificateHolder certificateHolder = new X509CertificateHolder(issuerCertEnc);
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

            //  CertID structure is used to uniquely identify certificates that are the subject of
            // an OCSP request or response and has an ASN.1 definition. CertID structure is defined in RFC 2560
            CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), certificateHolder, serialNumber);

            // basic request generation with nonce
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(id);

            // create details for nonce extension. The nonce extension is used to bind
            // a request to a response to prevent replay attacks. As the name implies,
            // the nonce value is something that the client should only use once within a reasonably small period.
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

            //to create the request Extension
            builder.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,false, new DEROctetString(nonce.toByteArray()))));

            return builder.build();
        } catch (Exception e) {
            throw new CertificateValidationException("Cannot generate OSCP Request with the given certificate", e);
        }
    }

    /**
     * Gets an ASN.1 encoded OCSP response (as defined in RFC 2560) from the given service URL. Currently supports
     * only HTTP.
     *
     * @param serviceUrl URL of the OCSP endpoint.
     * @param request    an OCSP request object.
     * @return OCSP response encoded in ASN.1 structure.
     * @throws CertificateValidationException
     *
     */
    private static OCSPResp getOCSPResponce(String serviceUrl, OCSPReq request, int retryCount)
            throws CertificateValidationException {

        OCSPResp ocspResp = null;
        try {
            //Todo: Use http client.
            byte[] array = request.getEncoded();
            if (serviceUrl.startsWith("http")) {
                HttpURLConnection con;
                URL url = new URL(serviceUrl);
                con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();

                //Check errors in response:
                if (con.getResponseCode() / 100 != 2) {
                    throw new CertificateValidationException("Error getting ocsp response." +
                            "Response code is " + con.getResponseCode());
                }

                //Get Response
                InputStream in = (InputStream) con.getContent();
                ocspResp = new OCSPResp(in);
            } else {
                throw new CertificateValidationException("Only http is supported for ocsp calls");
            }
        } catch (IOException e) {
            if(retryCount == 0) {
                throw new CertificateValidationException("Cannot get ocspResponse from url: " + serviceUrl, e);
            } else {
                log.info("Cant reach URI: " + serviceUrl + ". Retrying to connect - attempt " + retryCount);
                getOCSPResponce(serviceUrl, request, --retryCount);
            }
        }
        return ocspResp;
    }

    private static RevocationStatus getRevocationStatus(SingleResp resp) throws CertificateValidationException {
        Object status = resp.getCertStatus();
        if (status == CertificateStatus.GOOD) {
            return RevocationStatus.GOOD;
        } else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
            return RevocationStatus.REVOKED;
        } else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
            return RevocationStatus.UNKNOWN;
        }
        throw new CertificateValidationException("Cant recognize Certificate Status");
    }
}
