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

/**
 * X509 Certificate authenticator constants.
 *
 * @since 1.0.0
 */
public class X509CertificateConstants {
    public static final String AUTHENTICATOR_NAME = "x509CertificateAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "X509Certificate";
    public static final String USER_CERTIFICATE = "http://wso2.org/claims/userCertificate";
    public static final String DEFAULT = "Default";
    public static final String X_509_CERTIFICATE = "javax.servlet.request.X509Certificate";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String COMMON_AUTH = "commonauth";
    public static final String SERVLET_URL = "/x509-certificate-servlet";
    public static final String UTF_8 = "UTF-8";
    public static final String AUTH_ENDPOINT = "https://localhost:8443/x509-certificate-servlet";
    public static final String AUTHENTICATION_ENDPOINT = "AuthenticationEndpoint";
    public static final String AT_SIGN = "@";

}