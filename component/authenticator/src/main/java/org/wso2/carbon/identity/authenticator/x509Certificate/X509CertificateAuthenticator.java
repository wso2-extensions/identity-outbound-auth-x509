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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateUtil.isAccountDisabled;
import static org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateUtil.isAccountLock;

/**
 * Authenticator of X509Certificate.
 */
public class X509CertificateAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {

    private Pattern alternativeNamesPatternCompiled;
    private Pattern subjectPatternCompiled;
    private String subjectAttributePattern;
    private String alternativeNamePattern;

    private static final Log log = LogFactory.getLog(X509CertificateAuthenticator.class);

    public X509CertificateAuthenticator() {

        subjectAttributePattern = getAuthenticatorConfig().getParameterMap()
                .get(X509CertificateConstants.USER_NAME_REGEX);
        alternativeNamePattern = getAuthenticatorConfig().getParameterMap()
                .get(X509CertificateConstants.AlTN_NAMES_REGEX);
        if (alternativeNamePattern != null) {
            alternativeNamesPatternCompiled = Pattern.compile(alternativeNamePattern);
        }
        if (subjectAttributePattern != null) {
            subjectPatternCompiled = Pattern.compile(subjectAttributePattern);
        }
    }

    /**
     * Initialize the process and call servlet .
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        try {
            if (authenticationContext.isRetrying()) {
                String errorPageUrl;
                try {
                    // Check if internal hostname should be used for redirect.
                    boolean useInternalHostname = Boolean.parseBoolean(IdentityUtil.getProperty(
                            X509CertificateConstants.USE_INTERNAL_HOSTNAME_FOR_REDIRECT));

                    if (useInternalHostname) {
                        errorPageUrl = ServiceURLBuilder.create().addPath(X509CertificateConstants.ERROR_PAGE).build()
                                .getAbsoluteInternalURL();
                    } else {
                        errorPageUrl = ServiceURLBuilder.create().addPath(X509CertificateConstants.ERROR_PAGE).build()
                                .getAbsolutePublicURL();
                    }
                } catch (URLBuilderException e) {
                    throw new RuntimeException("Error occurred while building URL.", e);
                }
                String redirectUrl = errorPageUrl + ("?" + FrameworkConstants.SESSION_DATA_KEY + "="
                        + authenticationContext.getContextIdentifier()) + "&" + X509CertificateConstants.AUTHENTICATORS
                        + "=" + getName() + X509CertificateConstants.RETRY_PARAM_FOR_CHECKING_CERTIFICATE
                        + authenticationContext.getProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE);
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE, "");
                if (log.isDebugEnabled()) {
                    log.debug("Redirect to error page: " + redirectUrl);
                }
                httpServletResponse.sendRedirect(redirectUrl);
            } else {
                String authEndpoint = getAuthenticatorConfig().getParameterMap().
                        get(X509CertificateConstants.AUTHENTICATION_ENDPOINT_PARAMETER);
                if (StringUtils.isEmpty(authEndpoint)) {
                    authEndpoint = X509CertificateConstants.AUTHENTICATION_ENDPOINT;
                }
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                        authenticationContext.getQueryParams(), authenticationContext.getCallerSessionKey(),
                        authenticationContext.getContextIdentifier());
                if (log.isDebugEnabled()) {
                    log.debug("Request sent to " + authEndpoint);
                }
                httpServletResponse.sendRedirect(authEndpoint + ("?" + queryParams));
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while redirecting to the login page", e);
        }
    }

    /**
     * Validate the certificate.
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        Object object = authenticationContext.getProperty(X509CertificateConstants.X_509_CERTIFICATE);
        if (object == null) {
            object = httpServletRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE);
        }
        if (object != null) {
            X509Certificate[] certificates;
            if (object instanceof X509Certificate[]) {
                certificates = (X509Certificate[]) object;
            } else {
                throw new AuthenticationFailedException("Exception while casting the X509Certificate");
            }
            if (certificates.length > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("X509 Certificate Checking in servlet is done! ");
                }
                X509Certificate cert = certificates[0];
                String certAttributes = String.valueOf(cert.getSubjectX500Principal());
                Map<ClaimMapping, String> claims;
                claims = getSubjectAttributes(authenticationContext, certAttributes);
                String alternativeName;
                String subjectAttribute;
                if (alternativeNamePattern != null) {
                     alternativeName = getMatchedAlternativeName(cert, authenticationContext);
                     validateUsingSubject(alternativeName, authenticationContext, cert, claims);
                     if (log.isDebugEnabled()) {
                         log.debug("Certificate validated using the alternative name: " + alternativeName);
                     }
                    authenticationContext.setProperty(
                            X509CertificateConstants.X509_CERTIFICATE_USERNAME, alternativeName);
                } else if (subjectAttributePattern != null) {
                    subjectAttribute = getMatchedSubjectAttribute(certAttributes, authenticationContext);
                    validateUsingSubject(subjectAttribute, authenticationContext, cert, claims);
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate validated using the certificate subject attribute: " + subjectAttribute);
                    }
                    authenticationContext.setProperty(
                            X509CertificateConstants.X509_CERTIFICATE_USERNAME, subjectAttribute);
                } else {
                    String userName = null;
                    try {
                        userName = resolveUsernameFromIdentifier((String) authenticationContext.getProperty(
                                X509CertificateConstants.X509_CERTIFICATE_USERNAME), authenticationContext);
                    } catch (UserStoreException | AuthenticationFailedException e) {
                        throw new AuthenticationFailedException("Error occurred while resolving the username", e);
                    }

                    if (StringUtils.isEmpty(userName)) {
                        authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                                X509CertificateConstants.USERNAME_NOT_FOUND_FOR_X509_CERTIFICATE_ATTRIBUTE);
                        throw new AuthenticationFailedException(
                                "Couldn't find the username for X509Certificate's attribute");
                    } else {
                        validateUsingSubject(userName, authenticationContext, cert, claims);
                        if (log.isDebugEnabled()) {
                            log.debug("Certificate validated using the certificate username attribute: " + userName);
                        }
                    }
                }
            } else {
                throw new AuthenticationFailedException("X509Certificate object is null");
            }
        } else {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_FOUND_ERROR_CODE);
            throw new AuthenticationFailedException("Unable to find X509 Certificate in browser");
        }
    }

    /**
     * Resolves username of the subject attribute.
     *
     * @param identifier            identifier specified in the certificate
     * @param authenticationContext authentication context
     *
     * @return resolved username
     */
    private String resolveUsernameFromIdentifier(String identifier, AuthenticationContext authenticationContext)
            throws AuthenticationFailedException, UserStoreException {

        if (getAuthenticatorConfig().getParameterMap().containsKey(X509CertificateConstants.LOGIN_CLAIM_URIS)) {
            String[] attributeClaimUris = getAuthenticatorConfig().getParameterMap()
                    .get(X509CertificateConstants.LOGIN_CLAIM_URIS).split(",");

            String tenantDomain = authenticationContext.getTenantDomain();
            if (StringUtils.isEmpty(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }

            AbstractUserStoreManager aum = (AbstractUserStoreManager) X509CertificateUtil
                    .getUserRealmByTenantDomain(tenantDomain).getUserStoreManager();

            for (String attributeClaimUri : attributeClaimUris) {
                String[] usersWithClaim = aum.getUserList(attributeClaimUri, identifier, null);
                if (usersWithClaim.length == 1) {
                    return usersWithClaim[0];
                } else if (usersWithClaim.length > 1) {
                    authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                            X509CertificateConstants.USERNAME_CONFLICT);
                    throw new AuthenticationFailedException("Conflicting users with claim value: " + identifier);
                }
            }
        }
        return identifier;
    }

    /**
     * get String that matches UsernameRegex from subjectDN.
     *
     * @param certAttributes        certificate x500 principal
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    private String getMatchedSubjectAttribute(String certAttributes, AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        LdapName ldapDN;
        try {
            ldapDN = new LdapName(certAttributes);
        } catch (InvalidNameException e) {
            throw new AuthenticationFailedException("error occurred while get the certificate claims", e);
        }
        String userNameAttribute = getAuthenticatorConfig().getParameterMap().get(X509CertificateConstants.USERNAME);
        Set<String> matchedStringList = new HashSet<>();
        for (Rdn distinguishNames : ldapDN.getRdns()) {
            if (subjectPatternCompiled != null && userNameAttribute.equals(distinguishNames.getType())) {
                Matcher m = subjectPatternCompiled.matcher(String.valueOf(distinguishNames.getValue()));
                addMatchStringsToList(m, matchedStringList);
            }
        }
        if (matchedStringList.isEmpty()) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR_CODE);
            if (log.isDebugEnabled()) {
                log.debug(X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR);
            }
            throw new AuthenticationFailedException(
                    X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR);
        } else if (matchedStringList.size() > 1) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_MULTIPLE_MATCHES_ERROR_CODE);
            if (log.isDebugEnabled()) {
                log.debug("More than one value matched with the given regex, matches: " +
                        Arrays.toString(matchedStringList.toArray()));
            }
            throw new AuthenticationFailedException("More than one value matched with the given regex");
        } else {
            String matchedString = matchedStringList.toArray(new String[0])[0];
            if (log.isDebugEnabled()) {
                log.debug("Setting X509Certificate username attribute: " + userNameAttribute + " ,and value is "
                        + matchedString);
            }
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME, matchedString);
            return matchedString;
        }
    }

    /**
     * To add or validate the certificate against to the user name.
     *
     * @param userName              certificate's username
     * @param authenticationContext the authentication context
     * @param data                  certificate's data
     * @param claims                claims of the user
     * @param cert                  X509 certificate
     * @throws AuthenticationFailedException
     */
    private void addOrValidateCertificate(String userName, AuthenticationContext authenticationContext, byte[] data,
                                          Map<ClaimMapping, String> claims, X509Certificate cert) throws
            AuthenticationFailedException {

        boolean isUserCertValid;
        boolean isSelfRegistrationEnable = Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().
                get(X509CertificateConstants.ENFORCE_SELF_REGISTRATION));
        try {
            isUserCertValid = X509CertificateUtil
                    .validateCertificate(userName, authenticationContext, data, isSelfRegistrationEnable);
        } catch (AuthenticationFailedException e) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_VALIDATED_ERROR_CODE);
            throw new AuthenticationFailedException("Error in validating the user certificate", e);
        }
        String userStoreDomain;
        if (isUserCertValid) {
            try {
                userStoreDomain = getUserStoreDomainName(userName, authenticationContext);
                userName = UserCoreUtil.addDomainToName(userName, userStoreDomain);
                UserCoreUtil.setDomainInThreadLocal(userStoreDomain);
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Cannot find the user realm for the username: " + userName, e);
            }
        } else {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_NOT_VALID_ERROR_CODE);
            throw new AuthenticationFailedException("X509Certificate is not valid");
        }

        try {
            // Check whether user account is locked or not.
            if (isAccountLock(userName)) {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USER_ACCOUNT_LOCKED);
                throw new AuthenticationFailedException("Account is locked for user: " + userName);
            }

            // Check whether user account is disabled or not.
            if (isAccountDisabled(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName))) {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USER_ACCOUNT_DISABLED);
                throw new AuthenticationFailedException("Account is disabled for user: " + userName);
            }
        } catch (UserStoreException | AccountLockServiceException e) {
            throw new AuthenticationFailedException("User account lock/disable validation failed for user: "
                    + userName, e);
        }
        allowUser(userName, claims, cert, authenticationContext);
    }

    /**
     * Check canHandle.
     *
     * @param httpServletRequest http request
     * @return boolean status
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return (httpServletRequest.getParameter(X509CertificateConstants.SUCCESS) != null);
    }

    /**
     * Get context identifier.
     *
     * @param httpServletRequest http request
     * @return authenticator contextIdentifier
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
    }

    /**
     * Get the authenticator name.
     *
     * @return authenticator name
     */
    public String getName() {
        return X509CertificateConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get authenticator friendly name.
     *
     * @return authenticator friendly name
     */
    public String getFriendlyName() {
        return X509CertificateConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get username.
     *
     * @param authenticationContext authentication context
     * @return username username
     */
    private AuthenticatedUser getUsername(AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= authenticationContext.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = authenticationContext.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * @param authenticationContext authentication context
     * @param certAttributes        principal attributes from certificate.
     * @return claim map
     * @throws AuthenticationFailedException
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(AuthenticationContext authenticationContext, String
            certAttributes)
            throws AuthenticationFailedException {
        Map<ClaimMapping, String> claims = new HashMap<>();
        LdapName ldapDN;
        try {
            ldapDN = new LdapName(certAttributes);
        } catch (InvalidNameException e) {
            throw new AuthenticationFailedException("error occurred while get the certificate claims", e);
        }
        String userNameAttribute = getAuthenticatorConfig().getParameterMap().get(X509CertificateConstants.USERNAME);
        if (log.isDebugEnabled()) {
            log.debug("Getting username attribute: " + userNameAttribute);
        }
        for (Rdn distinguishNames : ldapDN.getRdns()) {
            claims.put(ClaimMapping.build(distinguishNames.getType(), distinguishNames.getType(),
                    null, false), String.valueOf(distinguishNames.getValue()));
            if (StringUtils.isNotEmpty(userNameAttribute)) {
                if (userNameAttribute.equals(distinguishNames.getType())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Setting X509Certificate username attribute: " + userNameAttribute
                                + "and value is " + distinguishNames.getValue());
                    }
                    authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME, String
                            .valueOf(distinguishNames.getValue()));
                }
            }
        }
        return claims;
    }

    /**
     * Allow user login into system.
     *
     * @param userName              username of the user.
     * @param claims                claim map.
     * @param cert                  x509 certificate.
     * @param authenticationContext authentication context.
     */
    private void allowUser(String userName, Map claims, X509Certificate cert,
                           AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUserObj;
        authenticatedUserObj = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName);
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(String.valueOf(cert.getSerialNumber()));
        authenticatedUserObj.setUserAttributes(claims);
        authenticationContext.setSubject(authenticatedUserObj);
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled
     */
    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get alternative name that matches the given regex from the certificate.
     * Handles all nine SAN types defined in RFC 5280. Types returned as String
     * by the JDK (rfc822Name, dNSName, directoryName, URI, iPAddress, registeredID)
     * are used directly. Types returned as raw DER byte[] by the JDK
     * (otherName, x400Address, ediPartyName) are decoded via Bouncy Castle.
     *
     * @param cert                  x509 certificate.
     * @param authenticationContext authentication context.
     * @return the matched alternative name string.
     * @throws AuthenticationFailedException if the certificate cannot be parsed, no SAN extension is found, or the
     * configured regex produces no match or multiple matches.
     */
    private String getMatchedAlternativeName(X509Certificate cert, AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        Set<String> matchedAlternativeNamesList = new HashSet<>();
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames == null) {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR_CODE);
                throw new AuthenticationFailedException(
                        X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR);
            }
            for (List<?> item : altNames) {
                Integer sanType = (Integer) item.get(0);
                Object value = item.get(1);
                String identity = null;
                if (value instanceof String) {
                    // Types 1,2,4,6,7,8 — JDK decodes these correctly including
                    // IP addresses (type 7) as dotted decimal e.g. "192.168.1.1"
                    identity = (String) value;
                } else if (value instanceof byte[]) {
                    // Types 0,3,5 — raw DER, decode via BC
                    identity = decodeDerSanValue((byte[]) value);
                }
                if (identity == null || identity.isEmpty()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skipping SAN entry of type " + sanType + ": could not decode to a usable string.");
                    }
                    continue;
                }
                Matcher m = alternativeNamesPatternCompiled.matcher(identity);
                addMatchStringsToList(m, matchedAlternativeNamesList);
            }
        } catch (CertificateParsingException e) {
            throw new AuthenticationFailedException("Failed to Parse the certificate", e);
        }
        if (matchedAlternativeNamesList.isEmpty()) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_REGEX_NO_MATCHES_ERROR_CODE);
            throw new AuthenticationFailedException("Regex Configured but no matches found for the given regex");
        } else if (matchedAlternativeNamesList.size() > 1) {
            authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                    X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_REGEX_MULTIPLE_MATCHES_ERROR_CODE);
            throw new AuthenticationFailedException("More than one match for the given regex");
        } else {
            return matchedAlternativeNamesList.toArray(new String[0])[0];
        }
    }

    /**
     * Decodes raw DER-encoded SAN byte[] values for the three types the JDK
     * does not decode to String: otherName (0), x400Address (3), ediPartyName (5).
     *
     * @param derBytes raw DER-encoded bytes as returned by the JDK's
     *                 {@link java.security.cert.X509Certificate#getSubjectAlternativeNames()}
     *                 for SAN types 0, 3, and 5.
     * @return null if the value cannot be decoded — the caller skips the entry.
     */
    private String decodeDerSanValue(byte[] derBytes) throws AuthenticationFailedException {

        try (ASN1InputStream decoder = new ASN1InputStream(derBytes)) {

            ASN1Primitive primitive = decoder.readObject();
            // otherName: SEQUENCE { OID, [0] EXPLICIT value }
            // Most common real-world case: Microsoft UPN carrying "user@domain.com"
            if (primitive instanceof ASN1Sequence) {
                ASN1Sequence seq = (ASN1Sequence) primitive;
                if (seq.size() >= 2) {
                    ASN1Primitive taggedWrapper = seq.getObjectAt(1).toASN1Primitive();
                    if (taggedWrapper instanceof ASN1TaggedObject) {
                        ASN1Primitive inner = ((ASN1TaggedObject) taggedWrapper).getBaseObject().toASN1Primitive();
                        if (inner instanceof ASN1TaggedObject) {
                            inner = ((ASN1TaggedObject) inner).getBaseObject().toASN1Primitive();
                        }
                        if (inner instanceof ASN1String) {
                            return ((ASN1String) inner).getString();
                        }
                    }
                }
            }
            // Fallback: if the primitive itself is a string (covers some x400Address/ediPartyName cases)
            if (primitive instanceof ASN1String) {
                return ((ASN1String) primitive).getString();
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to Parse the certificate", e);
        }
        return null;
    }

    /**
     * validate the certificate using the selected subject.
     *
     * @param subject               matched string or the username that uses to authenticate.
     * @param authenticationContext authenticationContext.
     * @param cert                  x509 certificate.
     * @param claims                user claims.
     */
    private void validateUsingSubject(String subject, AuthenticationContext authenticationContext,
                                      X509Certificate cert, Map<ClaimMapping, String> claims)
            throws AuthenticationFailedException {

        byte[] data;
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new AuthenticationFailedException(
                    "Encoded certificate is not found in the certificate with subjectDN: " + cert.getSubjectDN(), e);
        }
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);

        if (log.isDebugEnabled()) {
            log.debug("Getting X509Certificate username");
        }

        if (authenticatedUser != null) {
            if (log.isDebugEnabled()) {
                log.debug("Authenticated username is: " + authenticatedUser);
            }
            String authenticatedUserName = getAuthenticatedUserName(authenticatedUser);
            if (authenticatedUserName.equals(subject)) {
                addOrValidateCertificate(subject, authenticationContext, data, claims, cert);
            } else {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USERNAME_CONFLICT);
                throw new AuthenticationFailedException(
                        "Couldn't find X509 certificate to this authenticated user: " + authenticatedUserName);
            }
        } else {
            addOrValidateCertificate(subject, authenticationContext, data, claims, cert);
        }
    }

    /**
     * Check the authenticated user's tenant domain and verify whether it from super tenant or different tenant.
     *
     * @param authenticatedUser Get the authenticated user object from the authentication context  .
     */
    private String getAuthenticatedUserName(AuthenticatedUser authenticatedUser) {

        String userName = authenticatedUser.getAuthenticatedSubjectIdentifier();
        if (Boolean.parseBoolean(X509CertificateUtil.getX509Parameters()
                .get(X509CertificateConstants.SEARCH_ALL_USERSTORES))) {
            userName = UserCoreUtil.removeDomainFromName(userName);
        }
        if (userName.endsWith(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
            userName = authenticatedUser.getUserName();
        }
        return userName;
    }

    private void addMatchStringsToList(Matcher matcher, Set<String> matches) {

        while (matcher.find()) {
            matches.add(matcher.group());
        }
    }

    private String getUserStoreDomainName(String userIdentifier, AuthenticationContext authenticationContext)
            throws UserStoreException, AuthenticationFailedException {
        if (Boolean.valueOf(getAuthenticatorConfig().getParameterMap()
                .get(X509CertificateConstants.SEARCH_ALL_USERSTORES))) {
            UserStoreManager um = X509CertificateUtil.getUserRealm(userIdentifier).getUserStoreManager();
            String[] filteredUsers = um.listUsers(MultitenantUtils.getTenantAwareUsername(userIdentifier),
                    X509CertificateConstants.MAX_ITEM_LIMIT_UNLIMITED);
            if (filteredUsers.length == 1) {
                if (log.isDebugEnabled()) {
                    log.debug("User exists with the user name: " + userIdentifier);
                }
                return getDomainNameByUserIdentifier(filteredUsers[0]);
            } else if (filteredUsers.length > 1) {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USERNAME_CONFLICT);
                throw new AuthenticationFailedException("Conflicting users with user name: " + userIdentifier);
            } else if (getAuthenticatorConfig().getParameterMap()
                    .containsKey(X509CertificateConstants.LOGIN_CLAIM_URIS)) {
                String[] multiAttributeClaimUris = getAuthenticatorConfig().getParameterMap()
                        .get(X509CertificateConstants.LOGIN_CLAIM_URIS).split(",");
                AbstractUserStoreManager aum = (AbstractUserStoreManager)
                        X509CertificateUtil.getUserRealm(userIdentifier).getUserStoreManager();
                for (String multiAttributeClaimUri : multiAttributeClaimUris) {
                    String[] usersWithClaim = aum.getUserList(multiAttributeClaimUri, userIdentifier, null);
                    if (usersWithClaim.length == 1) {
                        return getDomainNameByUserIdentifier(usersWithClaim[0]);
                    } else if (usersWithClaim.length > 1) {
                        authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                                X509CertificateConstants.USERNAME_CONFLICT);
                        throw new AuthenticationFailedException(
                                "Conflicting users with claim value: " + userIdentifier);
                    }
                }
                throw new AuthenticationFailedException("Unable to find X509 Certificate's user in user store. ");
            } else {
                authenticationContext.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE,
                        X509CertificateConstants.USER_NOT_FOUND);
                throw new AuthenticationFailedException("Unable to find X509 Certificate's user in user store. ");
            }
        } else {
            if (userIdentifier.indexOf("/") > 0) {
                return getDomainNameByUserIdentifier(userIdentifier);
            } else {
                return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
            }
        }
    }

    private String getDomainNameByUserIdentifier (String userIdentifier) {

        if (userIdentifier.indexOf("/") > 0) {
            String[] subjectIdentifierSplits = userIdentifier.split("/", 2);
            return subjectIdentifierSplits[0];
        } else {
            return UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }
    }

}
