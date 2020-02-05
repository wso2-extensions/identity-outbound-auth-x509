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

package org.wso2.carbon.identity.authenticator.x509Certificate;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * Tests for X509CertificateAuthenticator.
 */
@PrepareForTest({ X509CertificateAuthenticator.class, X509CertificateUtil.class, FrameworkUtils.class, IdentityUtil.class, BaseCache.class, KeyStoreManager.class })
@PowerMockIgnore({ "javax.xml.*" })
public class X509CertificateAuthenticatorExtensionTest {

    private static final String CERT_ARUBAPEC_SPA_NG_CA_2 = "MIIE+DCCA+CgAwIBAgIQWHiRc5ymTq1oGnRZ1d4EWjANBgkqhkiG9w0BAQUFADBs\n"
            + "MQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQL\n" + "DBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMu\n"
            + "cC5BLiBORyBDQSAyMB4XDTA4MDgwNTAwMDAwMFoXDTI4MDgwNDIzNTk1OVowbDEL\n" + "MAkGA1UEBhMCSVQxGDAWBgNVBAoMD0FydWJhUEVDIFMucC5BLjEhMB8GA1UECwwY\n"
            + "Q2VydGlmaWNhdGlvbiBBdXRob3JpdHlCMSAwHgYDVQQDDBdBcnViYVBFQyBTLnAu\n" + "QS4gTkcgQ0EgMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO/HEcx0\n"
            + "kiFntBxRIySwU/wbb7384bnNwLjcOWqGKh/PFyjymeUiIMF3RgbvIg5O+B5V36CO\n" + "Eq6FsvhW8v2yI6JJ6MMMH3EdDAV35Y6mPOnXetsn3+mtkMi+u4C3fZ8f3UsmOL+S\n"
            + "7dxtvOqaax7FSURvNvPeTjQ/b8PKDgdLzR/Zn8bBH4IXCFsvPAHoQP9awWrzojwP\n" + "whWwHB5tn5sTHooPKzBULtRede4xSTp6HkCD3aqsj5Ve8QkQSIJT78I+NmL8AeJM\n"
            + "KC6ojvT50Xb42mDdPKccPkTP1zCX/+eYA4IOsx7nsrHkjdAVAjz5zLqFwzxGbtMN\n" + "o+LmUhfpZyYwxRkCAwEAAaOCAZQwggGQMBIGA1UdEwEB/wQIMAYBAf8CAQAwagYD\n"
            + "VR0fBGMwYTBfoF2gW4ZZaHR0cDovL29uc2l0ZWNybC5hcnViYXBlYy50cnVzdGl0\n" + "YWxpYS5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\n"
            + "dENSTC5jcmwwKgYDVR0SBCMwIaQfMB0xGzAZBgNVBAMTEkdPVlZTUC1DMS0yMDQ4\n" + "LTEtODA/BggrBgEFBQcBAQQzMDEwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmFy\n"
            + "dWJhcGVjLnRydXN0aXRhbGlhLml0MEYGA1UdIAQ/MD0wOwYKKwYBBAGB6C0BATAt\n" + "MCsGCCsGAQUFBwIBFh9odHRwczovL2NhLmFydWJhcGVjLml0L2Nwcy5odG1sMA4G\n"
            + "A1UdDwEB/wQEAwIBBjAqBgNVHREEIzAhpB8wHTEbMBkGA1UEAxMSR09WVlNQLUMx\n" + "LTIwNDgtMS04MB0GA1UdDgQWBBTy/2NAHBFC/czf8Vn2buiZhzFHeTANBgkqhkiG\n"
            + "9w0BAQUFAAOCAQEAFMS2EmV38HiH+QsIOdtFelRlRuCySjX/q2qh6eXsbxxJhXvI\n" + "+WQ8uLCFk+XjR8PMZHw9JAtk/YOYsZDhcJzBYb/WZTmxb5Kdb9a66G6tt3H3GpEh\n"
            + "a4sPsTEUhIhXeEA13Bna7/tFbMQ+I072297w3hBOFe9pgLNe8hkU3bSDBmq3EoB/\n" + "U2DGCpG/al/rWr/xuR+WzrMyalfAEieX2zGas7exnSoYUVguU+RsZPA6twqpvuJq\n"
            + "j51D5Qxhqdws1q08xiVloLwPtYRoaBpOK1OO+EbheaRYYfubK/ziIgX/gjWv9mhn\n" + "xtAJgqomBNWPrQrvnwm7htuBClgQpKuL8vYx6g==\n";

    private static final String CERT_CNS = "-----BEGIN CERTIFICATE-----\n" + "MIIFRzCCBC+gAwIBAgIQZEBl5/blMmfHc1RilpORiDANBgkqhkiG9w0BAQUFADBs\n"
            + "MQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQL\n" + "DBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMu\n"
            + "cC5BLiBORyBDQSAyMB4XDTE5MDYwMzAwMDAwMFoXDTIyMDYwMjIzNTk1OVowgcox\n" + "RzBFBgNVBAMMPkZSU0dMQzcyRDA1SDUwMUovNzQyMDA4MDIwMDI4MDg2NC44dmF0\n"
            + "eG1lSTR1UlJtaEtONzNVdGo4K3hWWG89MRwwGgYDVQQFExNJVDpGUlNHTEM3MkQw\n" + "NUg1MDFKMREwDwYDVQQqDAhHSUFOTFVDQTEOMAwGA1UEBAwFRkFSRVMxHDAaBgNV\n"
            + "BAoME0NhbWVyYSBkaSBDb21tZXJjaW8xEzARBgNVBAsMCkNDSUFBIFJvbWExCzAJ\n" + "BgNVBAYTAklUMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUhehToLJN3KDF\n"
            + "P+L9xkyCvUvwnawrbE/2M881EBE64Y5F42LHu6FyrnGDLqml0SQz9Ei0J8OYe58C\n" + "SKMbBvW29faXEvDHsPINJL7d4hbcbHHHfb+lJDSB+c+5DOZGvNvTVApGVEcHn2if\n"
            + "Qa5TSpdbDjY2EBldWVffrmn7dWiQtQIDAQABo4ICCDCCAgQwgfcGA1UdIASB7zCB\n" + "7DCBqwYFK0wQAgEwgaEwgZ4GCCsGAQUFBwICMIGRGoGOSWRlbnRpZmllcyBYLjUw\n"
            + "OSBhdXRoZW50aWNhdGlvbiBjZXJ0aWZpY2F0ZXMgaXNzdWVkIGZvciB0aGUgaXRh\n" + "bGlhbiBOYXRpb25hbCBTZXJ2aWNlIENhcmQgKENOUykgcHJvamVjdCBpbiBhY2Nv\n"
            + "cmRpbmcgdG8gdGhlIGl0YWxpYW4gcmVndWxhdGlvbjA8BgsrBgEEAYHoLQEBAjAt\n" + "MCsGCCsGAQUFBwIBFh9odHRwczovL2NhLmFydWJhcGVjLml0L2Nwcy5odG1sMFgG\n"
            + "A1UdHwRRME8wTaBLoEmGR2h0dHA6Ly9jcmwuYXJ1YmFwZWMuaXQvQXJ1YmFQRUNT\n" + "cEFDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5Qi9MYXRlc3RDUkwuY3JsMA4GA1UdDwEB\n"
            + "/wQEAwIFoDAfBgNVHSMEGDAWgBTy/2NAHBFC/czf8Vn2buiZhzFHeTAdBgNVHQ4E\n" + "FgQUYyMm97v1zBltmXlK3gEZHojPWAQwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUF\n"
            + "BzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDApBgNVHSUEIjAgBggrBgEFBQcD\n" + "AgYKKwYBBAGCNxQCAgYIKwYBBQUHAwQwDQYJKoZIhvcNAQEFBQADggEBAOn1Qp/k\n"
            + "9mL5DXyiapyIQZTV2TXXnzl9xB3VAN2MheqZlXVclEPHk9OSY4onfqAvyJRoSwos\n" + "8F3c/jtDQ/atmUkQ430hXDxavw99Nw4cewgPqo4yEFTbXsXDe5jIl6S3uh9OF5Oq\n"
            + "rQoDLhp6zUYdEw/u7mFtGs9fO239y4jmChfHibscxugc7a8gaDnImtwRT6Vh65xA\n" + "Avi/KoKxZsgJ7arV9V2wGt+jjIC2VVbINddsz+I4G2zInLhldfZDqpBmiBaqH7i+\n"
            + "qGKpM6fFilhE5K6oIiTKdNZh5kuoS+HPOKXcyP1lnf6drAA6xEShLDtP3NzIK0hr\n" + "pDgWlq3mC8Ky7/I=\n" + "-----END CERTIFICATE-----";

    private AuthenticatorConfig authenticatorConfig;

    class MockX509CertificateAuthenticator extends X509CertificateAuthenticator {

        @Override
        protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext)
                throws AuthenticationFailedException {
            processAuthenticationResponse(httpServletRequest, httpServletResponse, authenticationContext);

        }

        @Override
        protected AuthenticatorConfig getAuthenticatorConfig() {
            return authenticatorConfig;
        }
    }

    @DataProvider(name = "provideX509Certificates")
    public Object[][] provideTestData() throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(null);
        stepMap.put(1, stepConfig);
        sequenceConfig.setStepMap(stepMap);

        Map<String, String> map = new HashMap<>();
        map.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map.put(X509CertificateConstants.USERNAME, "CN");

        Map<String, String> map2 = new HashMap<>();
        map2.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map2.put(X509CertificateConstants.USERNAME, "CN");
        map2.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37");

        Map<String, String> map3 = new HashMap<>();
        map3.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map3.put(X509CertificateConstants.USERNAME, "CN");
        map3.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "1.1.1.1");

        Map<String, String> map4 = new HashMap<>();
        map4.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map4.put(X509CertificateConstants.USERNAME, "CN");
        map4.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37;1.1.1.1");

        Map<String, String> map5 = new HashMap<>();
        map5.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map5.put(X509CertificateConstants.USERNAME, "CN");
        map5.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37;2.5.29.32");

        Map<String, String> map6 = new HashMap<>();
        map6.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map6.put(X509CertificateConstants.USERNAME, "CN");
        map6.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37;2.5.29.32;2.5.29.35;2.5.29.32");
        map6.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_TRUST_STORE, "Fake trust store");

        Map<String, String> map7 = new HashMap<>();
        map7.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map7.put(X509CertificateConstants.USERNAME, "CN");
        map7.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37;2.5.29.32;2.5.29.35;2.5.29.32");
        map7.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_TRUST_STORE, "issuer.jks");
        KeyStore emptyKeystore = KeyStore.getInstance("JKS");
        emptyKeystore.load(null, "changeme".toCharArray());

        Map<String, String> map8 = new HashMap<>();
        map8.put(X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME, X509CertificateConstants.X509_CERTIFICATE_HEADER_NAME);
        map8.put(X509CertificateConstants.USERNAME, "CN");
        map8.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_REQUIRED_OID, "2.5.29.37;2.5.29.32;2.5.29.35;2.5.29.32");
        map8.put(X509CertificateConstants.X509_ISSUER_CERTIFICATE_TRUST_STORE, "issuer.jks");
        KeyStore arubaKeystore = KeyStore.getInstance("JKS");
        arubaKeystore.load(null, "changeme".toCharArray());
        arubaKeystore.setCertificateEntry("aruba", factory.generateCertificate(
                new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERT_ARUBAPEC_SPA_NG_CA_2))));

        //@formatter:off
        return new Object[][] {
        	{ sequenceConfig, map, false, null, null },
        	{ sequenceConfig, map2, false, null, null },
        	{ sequenceConfig, map3, true, X509CertificateConstants.X509_REQUIRED_POLICY_NOT_FOUND_ERROR_CODE, null },
        	{ sequenceConfig, map4, true, X509CertificateConstants.X509_REQUIRED_POLICY_NOT_FOUND_ERROR_CODE , null},
        	{ sequenceConfig, map5, false, null, null },
        	{ sequenceConfig, map6, true, X509CertificateConstants.X509_ISSUER_CERTIFICATE_NOT_TRUSTED_ERROR_CODE, null },
        	{ sequenceConfig, map7, true, X509CertificateConstants.X509_ISSUER_CERTIFICATE_NOT_TRUSTED_ERROR_CODE, emptyKeystore},
        	{ sequenceConfig, map8, false, null, arubaKeystore},
        };
        //@formatter: on
    }
    
	@Test(dataProvider = "provideX509Certificates")
	@SuppressWarnings("unchecked")
	public void testProcessAuthenticationResponse(Object sequenceConfig, Object config, boolean exceptionShouldThrown, String contextErrorCode, KeyStore issuerTrustStore) throws Exception {

		HttpServletRequest mockRequest = mock(HttpServletRequest.class);
		HttpServletResponse mockResponse = mock(HttpServletResponse.class);
		KeyStoreManager mockKeyStoreManager = mock(KeyStoreManager.class);
		BaseCache<String, String> mockCache = (BaseCache<String, String>) mock(BaseCache.class);

		AuthenticationContext authenticationContext = new AuthenticationContext();

		authenticatorConfig = new AuthenticatorConfig();

        authenticationContext.setSequenceConfig((SequenceConfig)sequenceConfig);
		authenticatorConfig.setParameterMap((Map<String, String>)config);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(Matchers.anyInt())).thenReturn(mockKeyStoreManager);
        when(mockKeyStoreManager.getKeyStore(Matchers.anyString())).thenReturn(issuerTrustStore);
        
		when(mockRequest.getHeader(X509CertificateConstants.X_509_CERTIFICATE))
				.thenReturn(CERT_CNS);
		when(mockCache.getValueFromCache(Matchers.anyString())).thenReturn(CERT_CNS);
		PowerMockito.whenNew(BaseCache.class).withAnyArguments().thenReturn(mockCache);

		X509CertificateAuthenticator spy = PowerMockito.spy(new MockX509CertificateAuthenticator());

		doReturn(authenticatorConfig).when(spy, "getAuthenticatorConfig");

		mockStatic(X509CertificateUtil.class);
		when(X509CertificateUtil.validateCertificate(Matchers.anyString(), Matchers.any(AuthenticationContext.class),
				any(byte[].class), Matchers.anyBoolean())).thenReturn(true);

		mockStatic(IdentityUtil.class);
		when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        if (exceptionShouldThrown) {
            try {
                spy.process(mockRequest, mockResponse, authenticationContext);
                fail("expected exception to be thrown but nothing was thrown");
            } catch (AuthenticationFailedException exception) {
                String errorCode = (String)authenticationContext.getProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE);
                if(contextErrorCode != null && !contextErrorCode.contentEquals(errorCode)) {
                		fail("Expected error code not set in context. Expected " + contextErrorCode +
                				" but received " + errorCode);
                }
            }
        } else {
            spy.process(mockRequest, mockResponse, authenticationContext);
        }
	}

}
