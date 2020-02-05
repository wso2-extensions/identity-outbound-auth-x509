/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 */
public class X509CertificateConstants {
    /*
     * Private Constructor will prevent the instantiation of this class directly.
	 */
    private X509CertificateConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "x509CertificateAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "X509Certificate";
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/claims/userCertificate";
    public static final String DEFAULT = "default";
    public static final String X_509_CERTIFICATE = "javax.servlet.request.X509Certificate";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String COMMON_AUTH = "commonauth";
    public static final String SERVLET_URL = "/x509-certificate-servlet";
    public static final String UTF_8 = "UTF-8";
    public static final String AUTHENTICATION_ENDPOINT = "https://localhost:8443/x509-certificate-servlet";
    public static final String AUTHENTICATION_ENDPOINT_PARAMETER = "AuthenticationEndpoint";
    public static final String USERNAME = "username";
    public static final String USER_NAME_REGEX = "UsernameRegex";
    public static final String AlTN_NAMES_REGEX= "AlternativeNamesRegex";
    public static final String ENFORCE_SELF_REGISTRATION = "EnforceSelfRegistration";
    public static final String SUCCESS = "success";
    public static final String RETRY_PARAM_FOR_CHECKING_CERTIFICATE =
            "&authFailure=true&errorCode=";
    public static final String ERROR_PAGE = "x509certificateauthenticationendpoint/x509CertificateError.jsp";
    public static final String CLAIM_URI = "setClaimURI";
    public static final String AUTHENTICATORS = "authenticators";
    public static final String X509_CERTIFICATE_ERROR_CODE = "X509CertificateErrorCode";
    public static final String X509_CERTIFICATE_NOT_FOUND_ERROR_CODE = "18013";
    public static final String USERNAME_CONFLICT = "20015";
    public static final String USERNAME_NOT_FOUND_FOR_X509_CERTIFICATE_ATTRIBUTE = "18003";
    public static final String X509_CERTIFICATE_USERNAME = "X509CertificateUsername";
    public static final String USER_NOT_FOUND = "17001";
    public static final String X509_CERTIFICATE_NOT_VALID_ERROR_CODE = "18015";
    public static final String X509_CERTIFICATE_NOT_VALIDATED_ERROR_CODE = "17003";
    public static final String X509_CERTIFICATE_ALTERNATIVE_NAMES_REGEX_MULTIPLE_MATCHES_ERROR_CODE = "17004";
    public static final String X509_CERTIFICATE_ALTERNATIVE_NAMES_REGEX_NO_MATCHES_ERROR_CODE = "17005";
    public static final String X509_CERTIFICATE_SUBJECTDN_REGEX_MULTIPLE_MATCHES_ERROR_CODE = "17006";
    public static final String X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR_CODE = "17007";
    public static final String X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR_CODE = "17008";
    public static final String X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR = "Regex Configured but no alternative "
            + "names in the certificate";
    public static final String X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR = "Regex configured but no matching "
            + "subjectRDN found for the given regex";
    public static final int MAX_ITEM_LIMIT_UNLIMITED = -1;
    public static final String SEARCH_ALL_USERSTORES = "SearchAllUserStores";
    public static final String LOGIN_CLAIM_URIS = "LoginClaimURIs";

    public static final String X509_CERTIFICATE_HEADER_NAME = "CertificateHeaderName";
    public static final String X509_CERTIFICATE_CACHE_NAME = "x509Cache";
    public static final String X509_ISSUER_CERTIFICATE_TRUST_STORE = "IssuerTrustStoreName";
    public static final String X509_ISSUER_CERTIFICATE_REQUIRED_OID = "IssuerRequiredOID";
    public static final String X509_ISSUER_CERTIFICATE_NOT_TRUSTED_ERROR_CODE = "17009";
    public static final String X509_UNABLE_TO_LOAD_TENANT_ERROR_CODE = "17010";
    public static final String X509_REQUIRED_POLICY_NOT_FOUND_ERROR_CODE =  "17011";
}
