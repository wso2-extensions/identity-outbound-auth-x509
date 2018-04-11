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

package org.wso2.carbon.identity.x509Certificate.validation;

/**
 * X509 Certificate validation constants.
 */
public class X509CertificateValidationConstants {

    private X509CertificateValidationConstants() {
    }

    public static final String CERT_VALIDATION_CONF_DIRECTORY = "security";
    public static final String CERT_VALIDATION_CONF_FILE = "certificate-validation.xml";

    public static final String VALIDATOR_CONF = "Validators";
    public static final String VALIDATOR_CONF_NAME = "name";
    public static final String VALIDATOR_CONF_DISPLAY_NAME = "displayName";
    public static final String VALIDATOR_CONF_ENABLE = "enable";
    public static final String VALIDATOR_CONF_PRIORITY = "priority";
    public static final String VALIDATOR_CONF_ELEMENT_PARAMETER = "Parameter";
    public static final String VALIDATOR_CONF_ELEMENT_PROPERTY_NAME = "name";
    public static final String VALIDATOR_CONF_FULL_CHAIN_VALIDATION = "fullChainValidation";
    public static final String VALIDATOR_CONF_RETRY_COUNT = "retryCount";
    public static final String VALIDATOR_CONF_REG_PATH = "repository/security/certificate/validator";

    public static final String TRUSTSTORE_CONF = "TrustStores";
    public static final String TRUSTSTORE_CONF_FILE = "truststoreFile";
    public static final String TRUSTSTORE_CONF_PASSWORD = "truststorePass";
    public static final String TRUSTSTORE_CONF_TYPE = "type";
    public static final String TRUSTSTORE_CONF_TYPE_DEFAULT = "JKS";
    public static final String CA_CERT_REG_PATH = "repository/security/certificate/certificate-authority";
    public static final String CA_CERT_REG_CRL = "crl";
    public static final String CA_CERT_REG_OCSP = "ocsp";
    public static final String CA_CERT_REG_CRL_OCSP_SEPERATOR = ",";
}