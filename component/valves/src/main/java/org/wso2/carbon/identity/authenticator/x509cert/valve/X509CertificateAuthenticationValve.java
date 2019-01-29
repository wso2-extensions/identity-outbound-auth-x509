/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.x509cert.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateConstants;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.servlet.ServletException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Valve for extracting the X509Certificate passed as a request header through SSL termination and
 * passing it as a request attribute.
 */
public class X509CertificateAuthenticationValve extends ValveBase {

    private static final String X509_REQUEST_HEADER = "X-SSL-CERT";
    private static final String X509CERT_NAME = "X509";
    private static final String CERT_PEM_START = "[-]+BEGIN CERTIFICATE[-]+[\t]*[\n]*";
    private static final Pattern PATTERN = Pattern.compile("[-]+(BEGIN CERTIFICATE)[-]+[\t]*[\n]*([^-]+)[-]+(END CERTIFICATE)[-]+");
    private static final String CERT_PEM_END = "[-]+END CERTIFICATE[-]+";

    private static Log log = LogFactory.getLog(X509CertificateAuthenticationValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
            extractAndSetX509certificate(request);
            getNext().invoke(request, response);
    }

    /**
     * Sets X509Certificate[] as an attribute in the request.
     * @param request
     */
    private void extractAndSetX509certificate(Request request) {

        X509Certificate certificate = getCertificate(request);
        
        if (certificate != null) {
            X509Certificate[] certificates = new X509Certificate[]{certificate};
            request.setAttribute(X509CertificateConstants.X_509_CERTIFICATE, certificates);
            
            if (log.isDebugEnabled()) {
                log.debug("X509certificate is set as an attribute in the request");
            }
        }
    }

    /**
     * Returns the X509Certificate extracted from the request header.
     * @param request
     * @return X509Certificate
     */
    private X509Certificate getCertificate(Request request) {

        X509Certificate certificate = null;

        String pemCert = request.getHeader(X509_REQUEST_HEADER);
        if (StringUtils.isNotEmpty(pemCert)) {
            Matcher matcher = PATTERN.matcher(pemCert);
            if (matcher.matches()) {
                String pemCertBody = pemCert.replaceAll(CERT_PEM_START, "")
                        .replaceAll(CERT_PEM_END, ""); // Need for the pem format
                byte[] certificateData = Base64.getMimeDecoder().decode(pemCertBody);

                try {
                    CertificateFactory cf = CertificateFactory.getInstance(X509CERT_NAME);
                    certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
                } catch (CertificateException e) {
                    log.error("Error occurred in generating certificate: " + request.getRequestURI(), e);
                }
            }
        }
        return certificate;
    }
}
