package org.wso2.carbon.identity.authenticator.x509Certificate;


import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

/**
 * Tests for X509CertificateAuthenticator.
 */
@PrepareForTest({X509CertificateAuthenticator.class, X509CertificateUtil.class, FrameworkUtils.class})
@PowerMockIgnore({ "javax.xml.*"})
public class X509CertificateAuthenticatorTest {

    private static final String CERTIFICATE_1 = "MIIEATCCAumgAwIBAgIJAIlDo4F1ZJvAMA0GCSqGSIb3DQEBCwUAMIG+MQ8wDQYD\n"
            + "VQQDDAZ3c28yaXMxEDAOBgNVBAMMBzEyM3dzbzIxEzARBgNVBAMMCndzbzJpcy5j\n"
            + "b20xFDASBgNVBAMMC2J1ZGRoaW1hMTIzMQswCQYDVQQGEwJTTDEQMA4GA1UECAwH\n"
            + "V2VzdGVybjEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwEV1NPMjELMAkGA1UE\n"
            + "CwwCUUExITAfBgkqhkiG9w0BCQEWEmJ1ZGRoaW1haEBtYWlsLmNvbTAgFw0xOTA1\n"
            + "MTUxMzA5NTFaGA8zMDE4MDkxNTEzMDk1MVowgb4xDzANBgNVBAMMBndzbzJpczEQ\n"
            + "MA4GA1UEAwwHMTIzd3NvMjETMBEGA1UEAwwKd3NvMmlzLmNvbTEUMBIGA1UEAwwL\n"
            + "YnVkZGhpbWExMjMxCzAJBgNVBAYTAlNMMRAwDgYDVQQIDAdXZXN0ZXJuMRAwDgYD\n"
            + "VQQHDAdDb2xvbWJvMQ0wCwYDVQQKDARXU08yMQswCQYDVQQLDAJRQTEhMB8GCSqG\n"
            + "SIb3DQEJARYSYnVkZGhpbWFoQG1haWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
            + "AQ8AMIIBCgKCAQEArAH3DmK6eBb2TloGaxTdG/EscOEXOkNd3Nu5fkmRsZ3WTJkf\n"
            + "q4KbVXBLgim61c/FgbXFgRrURQZ7yfuNLYsv6YHiQjSFNFCzcLK/KpBzROaK30wd\n"
            + "8MNheROfAQY8mfQEkEvECcl3jayY8+Gm86MZCO/YN+gDpPKuKC5iIfP0sy+AWNdH\n"
            + "Y7V7/ZHEzML18fZd+l8hfvSu3JqfxemNlrBOM5mtOAxFtwi5Np1JUdNhECoggMV6\n"
            + "L4NBnE1r9+IhhlKa5d66lcKxugYS+xVocEsBDJHRTLSSOU/F5vhlOlcBee6XynZc\n"
            + "jOdQQwrGONbBT73gMVBu/0GyQprD5NJZ1qxyswIDAQABMA0GCSqGSIb3DQEBCwUA\n"
            + "A4IBAQCXOAYF6BVt7wyEHremYyEeLDgP0cbAwbvDFxU2eZX6ye7uj/a25DvFZ/8c\n"
            + "bWxk93m6Tm2uGISorPsKsPO5Zu9/PXJU3c7LCxxcjWe0sO1IhPGTk7e5Rpn2cmbv\n"
            + "+LQdTl7dUSo6fuFbiOrruftjF+ZJKkj/9GKMp/S7eByc83roNvkLFNdqJ+Axvuel\n"
            + "jZMNEZzNY9c1V7jdo9Nn1dYDEtphMJWpNlt8VYsEAOf8+3QymeL/0N/BU/rELpud\n"
            + "OKu9rpLvzdhLvGlsO2CNasgknXeHLqVbHDiqg9pdWKyFCXPhRnl+XPgMm2jil1tR\n" + "JqnW8byHNmg6Oqfv0KgZrLV16zJA";

    private static final String CERTIFICATE_2 = "MIIDsjCCApqgAwIBAgIJALSmfizZKAkCMA0GCSqGSIb3DQEBCwUAMIGDMREwDwYD\n"
            + "VQQDDAhCdWRkaGltYTELMAkGA1UEBhMCU0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAO\n"
            + "BgNVBAcMB0NvbG9tYm8xDTALBgNVBAoMBFdTTzIxCzAJBgNVBAsMAlFBMSEwHwYJ\n"
            + "KoZIhvcNAQkBFhJidWRkaGltYWhAbWFpbC5jb20wIBcNMTkwNTE1MTMxNTUzWhgP\n"
            + "MzAxODA5MTUxMzE1NTNaMIGDMREwDwYDVQQDDAhCdWRkaGltYTELMAkGA1UEBhMC\n"
            + "U0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgNVBAoM\n"
            + "BFdTTzIxCzAJBgNVBAsMAlFBMSEwHwYJKoZIhvcNAQkBFhJidWRkaGltYWhAbWFp\n"
            + "bC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD5XG4mAQiRlU5b\n"
            + "yO2k5T5aQGOjnc2Drmu/uy240RqZ87ptkF2yJUdHPN5aGjbFy7ZZEDXh0B06Mvta\n"
            + "fB02eTU7qHiFoI8+i5UB5INtDZl0mlPQzP/YQ9Kv60gtgm/9KpmFavT68fITHHdl\n"
            + "hJkExlwmlj6qzw7sCFKwc2PNuoIRygP7YdqecRbn63cdJKBDFyomcysVFVjJT4a/\n"
            + "2gJrszJ7fb/jedjp7bMslebrmu7Es36uPc3M0lUIWipKPR6K3H1TL8ZqsTMgKyi6\n"
            + "vLvIGcP6xbj/gsYJjFt8Bq8vBNkC6okMX2u+nx2D1LqJTb7qKtSl/lOpdbLlo1eI\n"
            + "0CBUah3ZAgMBAAGjJTAjMCEGA1UdEQQaMBiCBHdzbzKCCHdzbzIuY29tggZ3c28y\n"
            + "aXMwDQYJKoZIhvcNAQELBQADggEBAHGjsGQrogJY03z69dKhzgKo2u3AY4MtQtmR\n"
            + "Gc74PYCdSKSsVcHSFGVroOHGNu3prji88/ipWrMSMmi3Y53/jKJ/MEtOVvWat0q3\n"
            + "eem1fu7BANb5cdhaQjUNE/ci9iYi7LVe/T/9N8NJe+iqR9olvRFT98tcQ/4WxXs8\n"
            + "oNZ/zXZeFirlk7RZgDVO/1xTzyoenEALvFXImLwsYssxXIpBd0wKc+11ViMafx8a\n"
            + "wVOoya8lZDYa2MmU0f1L7nfRMHFxOq7xhvC1PUN/x5lGFNa67QczrWXMTUExzHLC\n"
            + "qhoVNobDF97I7jJcSDoPLnw9kzIC+izUz82LphFa332QezoYgeU=";

    private static final String CERTIFICATE_3 = "MIIDhDCCAmwCCQCbjLuYujEEOjANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMC\n"
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

    private static final String CERTIFICATE_4 = "MIIDpDCCAowCCQD6qzKd7vtfWTANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC\n"
            + "U0wxETAPBgNVBAgMCFNvdXRoZXJuMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQK\n"
            + "DARXU28yMQswCQYDVQQLDAJRQTEgMB4GA1UEAwwXd3NvMmlzLDEyM2J1ZGRoaW1h\n"
            + "LHdzbzIxIDAeBgkqhkiG9w0BCQEWEWJ1ZGRoaW1hdUBhYmMuY29tMCAXDTE5MDUx\n"
            + "NTEzNDU0NFoYDzIxMTkwNDIxMTM0NTQ0WjCBkjELMAkGA1UEBhMCU0wxETAPBgNV\n"
            + "BAgMCFNvdXRoZXJuMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDARXU28yMQsw\n"
            + "CQYDVQQLDAJRQTEgMB4GA1UEAwwXd3NvMmlzLDEyM2J1ZGRoaW1hLHdzbzIxIDAe\n"
            + "BgkqhkiG9w0BCQEWEWJ1ZGRoaW1hdUBhYmMuY29tMIIBIjANBgkqhkiG9w0BAQEF\n"
            + "AAOCAQ8AMIIBCgKCAQEA/M/YV0kTiCpPyVLifdi9i/FosWJrkfjpyyQ2N8jKWuSK\n"
            + "QlyZ8S99UHwP0EgqOzNJWK5t62dFQt5DuVXAryISYSP6PRYyapBeON5nDx5+zX2/\n"
            + "88NfMENYBDOV3UTIqd3t45U1/7H/QCVU6Y/nWkD8UhFKRsp8AdWm2Y2ZcGfTJtLr\n"
            + "s6XIGB9zYjfpnTDoea7TmjJ0Wk07JZBayyyqGrvsZyIf/JlKf/ITywZhtaRbxxlo\n"
            + "bLU12i/RzYV/vh5awgbsKEr59EpmM8m4PRdhR5mN75VuusnpVfILShV92cMTBYyp\n"
            + "v1eZZ9z8Wp8n3o3wtaAIlU2Tam17OcH7f5Hkz5XCTQIDAQABMA0GCSqGSIb3DQEB\n"
            + "CwUAA4IBAQAGYqiugjx1Ak9o92xPr2wETtboyzHdDE6HYOlPDYtdh+gKZLb6MwSo\n"
            + "2zr931l3eBq1wG/G48zW1+GC09MYq+DrWDO8ZM17q3xuZZdflRRHs4IvdjHX7K3w\n"
            + "NNWNMUHeMlWEf8LufEOpw/3P3GH4i0SqZ7ld4nGlr2S3o4L6CY61qQCA6NmDZYHz\n"
            + "ybs2v5i+rXLjFCaw734DlBRN6LGapEVLwznjYHJIsADLXLWlqvotG2psw0cYGJl5\n"
            + "lnAa+yj6cL7kyF145DfB1QyUL4+tpEsiUBnFf6QaROEPhBZ9xl61zhg+6W8g+4q9\n" + "sPI+QGNS48ZDpXWJ8mXDTw0LoBuYKiKH";

    @DataProvider(name = "provideX509Certificates")
    public Object[][] createCertificates() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_1)));
        X509Certificate obj1[] = { cert1, null };

        SequenceConfig sequenceConfig1 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap1 = new HashMap<>();
        StepConfig stepConfig1 = new StepConfig();
        stepConfig1.setAuthenticatedUser(null);
        stepMap1.put(1, stepConfig1);
        sequenceConfig1.setStepMap(stepMap1);

        //Regex Configured but no alternative names in the certificate
        AuthenticatorConfig authenticatorConfig1 = new AuthenticatorConfig();
        Map<String, String> parameterMap1 = new HashMap<String, String>();
        parameterMap1.put(X509CertificateConstants.AlTN_NAMES_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap1.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap1.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap1.put(X509CertificateConstants.AUTHENTICATION_ENDPOINT_PARAMETER,
                "https://localhost:9443/x509" + "-certificate-servlet");
        authenticatorConfig1.setParameterMap(parameterMap1);

        //Authenticate Using alternative names
        X509Certificate cert2 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_2)));
        X509Certificate obj2[] = { cert2, null };

        SequenceConfig sequenceConfig2 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap2 = new HashMap<>();
        StepConfig stepConfig2 = new StepConfig();
        stepConfig2.setAuthenticatedUser(null);
        stepMap2.put(1, stepConfig2);
        sequenceConfig2.setStepMap(stepMap2);

        AuthenticatorConfig authenticatorConfig2 = new AuthenticatorConfig();
        Map<String, String> parameterMap2 = new HashMap<String, String>();
        parameterMap2.put(X509CertificateConstants.AlTN_NAMES_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap2.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap2.put(X509CertificateConstants.USERNAME, "CN");
        authenticatorConfig2.setParameterMap(parameterMap1);

        //Authenticate using username attribute when no pattern configurations
        X509Certificate cert3 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_3)));
        X509Certificate obj3[] = { cert3, null };

        SequenceConfig sequenceConfig3 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap3 = new HashMap<>();
        StepConfig stepConfig3 = new StepConfig();
        stepConfig3.setAuthenticatedUser(null);
        stepMap3.put(1, stepConfig3);
        sequenceConfig3.setStepMap(stepMap3);

        AuthenticatorConfig authenticatorConfig3 = new AuthenticatorConfig();
        Map<String, String> parameterMap3 = new HashMap<String, String>();
        parameterMap3.put(X509CertificateConstants.USERNAME, "CN");
        authenticatorConfig3.setParameterMap(parameterMap3);

        //Pattern configured no matching in subjectDN
        X509Certificate cert4 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_4)));
        X509Certificate obj4[] = { cert4, null };

        SequenceConfig sequenceConfig4 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap4 = new HashMap<>();
        StepConfig stepConfig4 = new StepConfig();
        stepConfig4.setAuthenticatedUser(null);
        stepMap4.put(1, stepConfig4);
        sequenceConfig4.setStepMap(stepMap4);

        AuthenticatorConfig authenticatorConfig4 = new AuthenticatorConfig();
        Map<String, String> parameterMap4 = new HashMap<String, String>();
        parameterMap4.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap4.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        authenticatorConfig4.setParameterMap(parameterMap4);

        //Authenticate using username attribute when pattern is configured
        AuthenticatorConfig authenticatorConfig5 = new AuthenticatorConfig();
        Map<String, String> parameterMap5 = new HashMap<String, String>();
        parameterMap5.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap5.put(X509CertificateConstants.USER_NAME_REGEX, "\\d\\d\\d[a-zA-Z]{8}");
        authenticatorConfig5.setParameterMap(parameterMap5);

        return new Object[][] {
                {
                        obj1, authenticatorConfig1, sequenceConfig1, true,
                        X509CertificateConstants.X509_CERTIFICATE_NO_ALTERNATIVE_NAMES_ERROR
                }, { obj2, authenticatorConfig2, sequenceConfig2, false, "" },
                { obj3, authenticatorConfig3, sequenceConfig3, false, "" }, {
                        obj4, authenticatorConfig4, sequenceConfig4, true,
                        X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR
                }, {
                        obj4, authenticatorConfig5, sequenceConfig4, false, ""
                },
                };
    }

    class MockX509CertificateAuthenticator extends X509CertificateAuthenticator {
        @Override
        protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext)
                throws AuthenticationFailedException {
            processAuthenticationResponse(httpServletRequest, httpServletResponse, authenticationContext);

        }
    }

    @Test(dataProvider = "provideX509Certificates")
    public void testProcessAuthenticationResponse(X509Certificate[] certificateArray, Object object1, Object object2,
            boolean exceptionShouldThrown, String exceptionMessage

    ) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        when(mockRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE)).thenReturn(certificateArray);
        X509CertificateAuthenticator x509CertificateAuthenticator = new MockX509CertificateAuthenticator();
        X509CertificateAuthenticator spy = PowerMockito.spy(x509CertificateAuthenticator);
        AuthenticatorConfig authenticatorConfig = (AuthenticatorConfig) object1;
        ;
        SequenceConfig sequenceConfig = (SequenceConfig) object2;
        authenticationContext.setSequenceConfig(sequenceConfig);
        doReturn(authenticatorConfig).when(spy, "getAuthenticatorConfig");
        mockStatic(X509CertificateUtil.class);
        when(X509CertificateUtil
                .validateCertificate(Matchers.anyString(), Matchers.any(AuthenticationContext.class), any(byte[].class),
                        Matchers.anyBoolean())).thenReturn(true);
        if (exceptionShouldThrown) {
            try {
                spy.process(mockRequest, mockResponse, authenticationContext);
                fail("expected exception to be thrown but nothing was thrown");
            } catch (AuthenticationFailedException exception) {
                if (!exception.getMessage().equals(exceptionMessage)) {
                    fail("expected exception was not occured.");
                }
            }
        } else {
            spy.process(mockRequest, mockResponse, authenticationContext);
        }
    }

}
