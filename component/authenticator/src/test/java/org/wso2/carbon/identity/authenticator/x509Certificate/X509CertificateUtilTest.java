/*
 *  Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManagerImpl;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.fail;

@PrepareForTest({X509CertificateUtil.class, FileBasedConfigurationBuilder.class, IdentityTenantUtil.class,
        X509CertificateRealmServiceComponent.class, AbstractUserStoreManager.class})
@PowerMockIgnore({"javax.xml.*"})
public class X509CertificateUtilTest extends PowerMockTestCase {

    private static final String CERT_WITH_ONE_CN_NO_AlTERNATIVE_NAMES =
            "MIIDhDCCAmwCCQCbjLuYujEEOjANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMC\n"
                    + "U0wxEDAOBgNVBAgMB1dlc3Rlcm4xETAPBgNVBAcMCFRhbmdhbGxlMQ0wCwYDVQQK\n"
                    + "DARXU28yMQswCQYDVQQLDAJRQTEPMA0GA1UEAwwGd3NvMmlzMSEwHwYJKoZIhvcN\n"
                    + "AQkBFhJidWRkaGltYXVAd3NvMi5jb20wIBcNMTkwNTE1MTMzOTMwWhgPMjExOTA0\n"
                    + "MjExMzM5MzBaMIGCMQswCQYDVQQGEwJTTDEQMA4GA1UECAwHV2VzdGVybjERMA8G\n"
                    + "A1UEBwwIVGFuZ2FsbGUxDTALBgNVBAoMBFdTbzIxCzAJBgNVBAsMAlFBMQ8wDQYD\n"
                    + "VQQDDAZ3c28yaXMxITAfBgkqhkiG9w0BCQEWEmJ1ZGRoaW1hdUB3c28yLmNvbTCC\n"
                    + "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL/qkwNCSehYeaUQSg+1Jr7J\n"
                    + "U+r60DZnhak0hSUCvMesY1l8JfXjp/Ml9pjndD8XU1QOqnSZXLKPIpC55vXTPAfi\n"
                    + "TIOgbeDDw6X+mnkE1XSzuwuru/9vdoGMIx4uF0SJhy1Bt1ZwmnKarwlQY0BNeDOg\n"
                    + "LEgAKofsZdWQ3XrSPCohXej193+t9VlX+/67oqpm/t9Q4F71wBSj02iqEw2Wsmze\n"
                    + "VrbFhliBko+WA5hk6/l5rmtPyl62+fSwV/1Xt7bylqbHuYeXzVJPsgMQTgg6WOsi\n"
                    + "P7/51DnbWN7LBbvqszCRl0zWNn6DrHVgxhNX09jZB14+PLe84uviy52rZb9M+SsC\n"
                    + "AwEAATANBgkqhkiG9w0BAQsFAAOCAQEABasjO16I3cNrTmvd2TFzRdSXWg9G2kMa\n"
                    + "8USm1U1BadnkaDTeKUK53yTndmAizlYUHqQHWJws+tZNWX2oyXP7caps64VL4Ojb\n"
                    + "L3iOq3zZvAz7Fehdk84lhgZl+gX8BX+EnLDdv+/ImuHBwsYWN2ibKuzsKZP/fbDT\n"
                    + "y0Q5NlOHiTTJ/njdDU7FIsz2m3Y3C/KFAoQvCmCjSJL1xRiaRgfNl6vlkr99eXqs\n"
                    + "mv4JKSOXDgc9r0SbEsE1UBL/ShEaFZJPGv7afom+tGfyGoTUspWp5RkiCAi0z0Ie\n"
                    + "+gBGPDN+2G5+JD9UgcyjscttPDVR6C/Bkf11RA2FCjO5VmRKGoFRRg==";
    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private AbstractUserStoreManager userStoreManager;
    @Mock
    private RevocationValidationManagerImpl revocationValidationManagerImpl;

    @Test(dataProvider = "x509CertificateUtilDataProvider")
    public void testValidateCertificate(String searchAllUserStores, String[] userList, boolean isUserExistsInStore,
                                        boolean expectedResult, boolean isExceptionExpected,
                                        String expectedExceptionMessage) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_ONE_CN_NO_AlTERNATIVE_NAMES)));
        byte[] data;
        data = cert.getEncoded();

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap.put(X509CertificateConstants.SEARCH_ALL_USERSTORES, searchAllUserStores);
        authenticatorConfig.setParameterMap(parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(X509CertificateConstants.AUTHENTICATOR_NAME))
                .thenReturn(authenticatorConfig);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);

        mockStatic(X509CertificateRealmServiceComponent.class);
        when(X509CertificateRealmServiceComponent.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);

        userStoreManager = PowerMockito.mock(AbstractUserStoreManager.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        when(userStoreManager.listUsers(anyString(), anyInt())).thenReturn(userList);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(isUserExistsInStore);

        PowerMockito.whenNew(RevocationValidationManagerImpl.class).withNoArguments()
                .thenReturn(revocationValidationManagerImpl);

        if (!isExceptionExpected) {
            boolean result =
                    X509CertificateUtil.validateCertificate("user1", new AuthenticationContext(), data,
                            false);
            Assert.assertEquals(result, expectedResult);
        } else {
            try {
                boolean result =
                        X509CertificateUtil.validateCertificate("user1", new AuthenticationContext(), data,
                                false);
                fail("expected exception to be thrown but nothing was thrown");
            } catch (Exception e) {
                Assert.assertEquals(e.getMessage(), expectedExceptionMessage);
            }
        }
    }

    @DataProvider(name = "x509CertificateUtilDataProvider")
    public Object[][] provideTestData() {

        String[] listUsers1 = new String[1];
        listUsers1[0] = "user1";

        return new Object[][]{
                {
                    "true", listUsers1, true, true, false, ""
                },
                {
                    "false", listUsers1, true, true, false, ""
                },
                {
                    "false", listUsers1, false, true, true, " Unable to find X509 Certificate's user in user store. "
                },
        };
    }
}