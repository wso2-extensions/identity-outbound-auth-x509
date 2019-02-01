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
package org.wso2.carbon.identity.authenticator.x509cert.valve.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;

public class X509ServerConfiguration {

    private static Log log = LogFactory.getLog(X509ServerConfiguration.class);
    private static X509ServerConfiguration instance;
    private static final String CONFIG_ELEM_X509 = "X509";
    private static final String CONFIG_ELEM_X509_REQUEST_HEADER = "X509RequestHeaderName";

    private String x509requestHeader = "X-SSL-CERT";

    private X509ServerConfiguration() {

        buildX509ServerConfiguration();
    }

    public static X509ServerConfiguration getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (X509ServerConfiguration.class) {
                if (instance == null) {
                    instance = new X509ServerConfiguration();
                }
            }
        }
        return instance;
    }

    /**
     * @return name of the X509 request header
     */
    public String getX509requestHeader() {

        return x509requestHeader;
    }

    private void buildX509ServerConfiguration() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement x509Elem = configParser.getConfigElement(CONFIG_ELEM_X509);

        if (x509Elem == null) {
            log.debug("X509 Request header configuration is not enabled");
            return;
        }

        // Read X509 Configurations.
        parseX509ServerConfigurations(x509Elem);
    }

    private void parseX509ServerConfigurations(OMElement x509Elem) {

        // Get the configured name of the X509Request header.
        String requestHeaderName =
                x509Elem.getFirstChildWithName(getQNameWithIdentityNS(CONFIG_ELEM_X509_REQUEST_HEADER))
                        .getText().trim();
        if (requestHeaderName != null) {
            x509requestHeader = requestHeaderName;
        }
    }

    private QName getQNameWithIdentityNS(String localPart) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

}
