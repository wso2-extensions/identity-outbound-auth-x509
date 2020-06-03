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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

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
import static org.testng.Assert.fail;

/**
 * Tests for X509CertificateAuthenticator.
 */
@PrepareForTest({X509CertificateAuthenticator.class, X509CertificateUtil.class, FrameworkUtils.class, IdentityUtil
        .class})
@PowerMockIgnore({ "javax.xml.*"})
public class X509CertificateAuthenticatorTest {

    private static final String CERT_WITH_NO_ALTERNATIVE_NAMES =
            "MIIEATCCAumgAwIBAgIJAIlDo4F1ZJvAMA0GCSqGSIb3DQEBCwUAMIG+MQ8wDQYD\n"
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
                    + "OKu9rpLvzdhLvGlsO2CNasgknXeHLqVbHDiqg9pdWKyFCXPhRnl+XPgMm2jil1tR\n"
                    + "JqnW8byHNmg6Oqfv0KgZrLV16zJA";

    private static final String CERT_WITH_ALTERNATIVE_NAMES =
            "MIIDsjCCApqgAwIBAgIJALSmfizZKAkCMA0GCSqGSIb3DQEBCwUAMIGDMREwDwYD\n"
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

    private static final String CERT_WITH_SIMILAR_ALTERNATIVE_NAMES =
            "MIIDsDCCApigAwIBAgIJAK4zivrElc0IMA0GCSqGSIb3DQEBCwUAMIGDMREwDwYD\n" +
                    "VQQDDAhCdWRkaGltYTELMAkGA1UEBhMCU0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAO\n" +
                    "BgNVBAcMB0NvbG9tYm8xDTALBgNVBAoMBFdTTzIxCzAJBgNVBAsMAlFBMSEwHwYJ\n" +
                    "KoZIhvcNAQkBFhJidWRkaGltYXVAd3NvMi5jb20wIBcNMTkwNzE2MDQyMzEwWhgP\n" +
                    "MzAxODExMTYwNDIzMTBaMIGDMREwDwYDVQQDDAhCdWRkaGltYTELMAkGA1UEBhMC\n" +
                    "U0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgNVBAoM\n" +
                    "BFdTTzIxCzAJBgNVBAsMAlFBMSEwHwYJKoZIhvcNAQkBFhJidWRkaGltYXVAd3Nv\n" +
                    "Mi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpZ7WOU16ixjbC\n" +
                    "bXdwGraMnqnlgoi303yiQqlp2K9VNfGOmgNQatWen0t1UVr61wF8yYGh2rsYgn+a\n" +
                    "8paufQUPCYZxTEGQiOdOgDMpNmYo6du6+c/zrjpsgphyHr14FOTp1iTCIpfjupV1\n" +
                    "wPTyroyDrHdo2Jn8r7WqurIIU4AbYA7ckuUj/KjaJ/M6kf+pDWyIRoh0JLReYc8Q\n" +
                    "ynhXr7kAjyFqj6+gZwAbHxrHkrEsa2hV44PRWZ1PPDqL+0UO/xMaAnnvwltgxBUi\n" +
                    "HKQ1WX5puUOh/dA49oDllJkhzqwgyx41sQXlSaVgJjITeWRBgo6xzj3fwuozpFKX\n" +
                    "o4ZypHL3AgMBAAGjIzAhMB8GA1UdEQQYMBaCBHdzbzKCCHdzbzIuY29tggR3c28y\n" +
                    "MA0GCSqGSIb3DQEBCwUAA4IBAQBSK0JkZrbZobdC4xYHmHryUnFUnFYYAofg4LUF\n" +
                    "BQmlCcCJGFpGPm7fCXs4cHxgHOU3yJHmCjXiOEE76w8HSCQqXd6dNHL1FLm7JjA5\n" +
                    "LFflxbYsNreU5ZINdDTfoZlRItt2Gx2ZHkzcATIfmrPSp85vX8Fzmfm3AU5i3qWe\n" +
                    "8kf2fNgB9LlNWDY5WOiiYGQc+FMwYgKp2d4c7w3+ZtSQrVG/Xtjja2XWOWvmlWwK\n" +
                    "pxozr62/M7TRedsxI5Oto2oXLFezu1GBXwi4AZzjLHUl5jRGhLnCYkNjufFf/DCG\n" +
                    "yAVvzLUt0gatoGIu5vxoekNIUeya6iG2AhocJc4HBLOyxMq7";

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

    private static final String CERT_WITH_COMMA_SEPERATED_CN =
            "MIIDpDCCAowCCQD6qzKd7vtfWTANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC\n"
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
                    + "lnAa+yj6cL7kyF145DfB1QyUL4+tpEsiUBnFf6QaROEPhBZ9xl61zhg+6W8g+4q9\n"
                    + "sPI+QGNS48ZDpXWJ8mXDTw0LoBuYKiKH";

    private static final String CERT_WITH_SUBJECT_IN_THE_EMAIL =
            "MIIDyDCCArCgAwIBAgIJAMuvHuw9SZ+IMA0GCSqGSIb3DQEBCwUAMIGFMRMwEQYD\n"
                    + "VQQDDApjb21tb25OYW1lMQswCQYDVQQGEwJTTDEQMA4GA1UECAwHV2VzdGVybjEQ\n"
                    + "MA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwEV1NPMjELMAkGA1UECwwCUUExITAf\n"
                    + "BgkqhkiG9w0BCQEWEmJ1ZGRoaW1haEB3c28yLmNvbTAgFw0xOTA1MTYwNzU4MDha\n"
                    + "GA8zMDE4MDkxNjA3NTgwOFowgYUxEzARBgNVBAMMCmNvbW1vbk5hbWUxCzAJBgNV\n"
                    + "BAYTAlNMMRAwDgYDVQQIDAdXZXN0ZXJuMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYD\n"
                    + "VQQKDARXU08yMQswCQYDVQQLDAJRQTEhMB8GCSqGSIb3DQEJARYSYnVkZGhpbWFo\n"
                    + "QHdzbzIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm8rszlo/\n"
                    + "t1BEZg7kcUt1LaAkbP2q1wFcf63SMOewMbOSVUr/48iE2KIG7l1fOBo7up2uA4N0\n"
                    + "TYNWfjheAtglvFMcxGUiixxlH/AikAdpO1ClNisvC+MMwPA3rQkjQToPlLvLTBD/\n"
                    + "+y9LuHmD/s0V15xGKlNHUoA2s1JGRmcUtWRK/XrxRcQAMRaf1mI72FUwlDAvzQYe\n"
                    + "amqlMIpsrzDMm7VSzleL2p3xjMPV9P0tHtCucL+THV35Y4ktVLpYbgLzGRUgPUCI\n"
                    + "GXEgbeubqMS7Dj011fFYmHzM8CB+oHbW+mpx/KyD2HuVsRKOAxKwBev0kprmpu18\n"
                    + "vwLrOGltlfOM4QIDAQABozcwNTAzBgNVHREELDAqgg53d3cuZ29vZ2xlLmNvbYIJ\n"
                    + "d3d3LmFjLmxrgg13d3cubXJ0LmFjLmxrMA0GCSqGSIb3DQEBCwUAA4IBAQCOhFvY\n"
                    + "NmdW+PKwiHBD486MATJSfXXbOxkdB1OTNx++iWEdOupnTmQa9sPMA5dfCrsehf04\n"
                    + "RtERe4LbSJoug3T4OIww2/6kRxP52+zZnwpg7GgMFN7RMgUXE9ptHC0mOnIL+LpC\n"
                    + "vD9CDN2WBvnCHBA/x21Q+fTjchDNYG96YLJn2uW6pwPuRAzSBFpUmko6KMUgqUVJ\n"
                    + "MnL4jtEI7tHs89GB+tfurD2dsSLW5ghXaDwmZTNuaUOgD8SRYwh0AG+en1Xk2v3/\n"
                    + "73zDq+0+CCuZv87EyQbA5QobwBlYNe45ocyxSzocJLTapVkcXytDr/+ZhhdB7ybL\n" + "UZoGqB7ayed6KBFi";

    @DataProvider(name = "provideX509Certificates")
    public Object[][] provideTestData() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_NO_ALTERNATIVE_NAMES)));
        X509Certificate certificateArrayObject1[] = { cert1, null };

        SequenceConfig sequenceConfig1 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap1 = new HashMap<>();
        StepConfig stepConfig1 = new StepConfig();
        stepConfig1.setAuthenticatedUser(null);
        stepMap1.put(1, stepConfig1);
        sequenceConfig1.setStepMap(stepMap1);

        //Regex Configured but no alternative names in the certificate
        AuthenticatorConfig authenticatorConfig1 = new AuthenticatorConfig();
        Map<String, String> parameterMap1 = new HashMap<>();
        parameterMap1.put(X509CertificateConstants.AlTN_NAMES_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap1.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap1.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap1.put(X509CertificateConstants.AUTHENTICATION_ENDPOINT_PARAMETER,
                "https://localhost:9443/x509" + "-certificate-servlet");
        authenticatorConfig1.setParameterMap(parameterMap1);

        //Authenticate Using alternative names
        X509Certificate cert2 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_ALTERNATIVE_NAMES)));
        X509Certificate certificateArrayObject2[] = { cert2, null };

        SequenceConfig sequenceConfig2 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap2 = new HashMap<>();
        StepConfig stepConfig2 = new StepConfig();
        stepConfig2.setAuthenticatedUser(null);
        stepMap2.put(1, stepConfig2);
        sequenceConfig2.setStepMap(stepMap2);

        AuthenticatorConfig authenticatorConfig2 = new AuthenticatorConfig();
        Map<String, String> parameterMap2 = new HashMap<>();
        parameterMap2.put(X509CertificateConstants.AlTN_NAMES_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap2.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap2.put(X509CertificateConstants.USERNAME, "CN");
        authenticatorConfig2.setParameterMap(parameterMap1);

        //Authenticate using username attribute when no pattern configurations
        X509Certificate cert3 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_ONE_CN_NO_AlTERNATIVE_NAMES)));
        X509Certificate certificateArrayObject3[] = { cert3, null };

        SequenceConfig sequenceConfig3 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap3 = new HashMap<>();
        StepConfig stepConfig3 = new StepConfig();
        stepConfig3.setAuthenticatedUser(null);
        stepMap3.put(1, stepConfig3);
        sequenceConfig3.setStepMap(stepMap3);

        AuthenticatorConfig authenticatorConfig3 = new AuthenticatorConfig();
        Map<String, String> parameterMap3 = new HashMap<>();
        parameterMap3.put(X509CertificateConstants.USERNAME, "CN");
        authenticatorConfig3.setParameterMap(parameterMap3);

        //Pattern configured no matching in subjectDN
        X509Certificate cert4 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_COMMA_SEPERATED_CN)));
        X509Certificate certificateArrayObject4[] = { cert4, null };

        SequenceConfig sequenceConfig4 = new SequenceConfig();
        Map<Integer, StepConfig> stepMap4 = new HashMap<>();
        StepConfig stepConfig4 = new StepConfig();
        stepConfig4.setAuthenticatedUser(null);
        stepMap4.put(1, stepConfig4);
        sequenceConfig4.setStepMap(stepMap4);

        AuthenticatorConfig authenticatorConfig4 = new AuthenticatorConfig();
        Map<String, String> parameterMap4 = new HashMap<>();
        parameterMap4.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap4.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        authenticatorConfig4.setParameterMap(parameterMap4);

        //Authenticate using username attribute when pattern is configured
        AuthenticatorConfig authenticatorConfig5 = new AuthenticatorConfig();
        Map<String, String> parameterMap5 = new HashMap<>();
        parameterMap5.put(X509CertificateConstants.USERNAME, "CN");
        parameterMap5.put(X509CertificateConstants.USER_NAME_REGEX, "\\d\\d\\d[a-zA-Z]{8}");
        authenticatorConfig5.setParameterMap(parameterMap5);

        //Authenticate using email attribute when pattern is configured
        X509Certificate cert6 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_SUBJECT_IN_THE_EMAIL)));
        X509Certificate certificateArrayObject6[] = { cert6, null };
        AuthenticatorConfig authenticatorConfig6 = new AuthenticatorConfig();
        Map<String, String> parameterMap6 = new HashMap<>();
        parameterMap6.put(X509CertificateConstants.USERNAME, "EMAILADDRESS");
        parameterMap6.put(X509CertificateConstants.USER_NAME_REGEX, "[a-zA-Z]{3}\\d");
        authenticatorConfig6.setParameterMap(parameterMap6);

        // Authenticate Using similar alternative names.
        X509Certificate cert7 = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(
                        CERT_WITH_SIMILAR_ALTERNATIVE_NAMES)));
        X509Certificate certificateArrayObject7[] = { cert7, null };

        AuthenticatorConfig authenticatorConfig7 = new AuthenticatorConfig();
        Map<String, String> parameterMap7 = new HashMap<>();
        parameterMap7.put(X509CertificateConstants.AlTN_NAMES_REGEX, "^.*wso2$");
        parameterMap7.put(X509CertificateConstants.USER_NAME_REGEX, "^[a-zA-Z]{3}.[a-zA-Z]{2}$");
        parameterMap7.put(X509CertificateConstants.USERNAME, "CN");
        authenticatorConfig7.setParameterMap(parameterMap7);
        
        return new Object[][] {
                {
                        certificateArrayObject1, authenticatorConfig1, sequenceConfig1, true,
                        X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR
                },
                {
                        certificateArrayObject2, authenticatorConfig2, sequenceConfig2, false, ""
                },
                {
                        certificateArrayObject3, authenticatorConfig3, sequenceConfig3, false, "" },
                {
                        certificateArrayObject4, authenticatorConfig4, sequenceConfig4, true,
                        X509CertificateConstants.X509_CERTIFICATE_SUBJECTDN_REGEX_NO_MATCHES_ERROR
                },
                {
                        certificateArrayObject4, authenticatorConfig5, sequenceConfig4, false, ""
                },
                {
                        certificateArrayObject6, authenticatorConfig6, sequenceConfig4, false, ""
                },
                {
                        certificateArrayObject7, authenticatorConfig7, sequenceConfig2, false, ""
                },
                };
    }
    private AuthenticatorConfig authenticatorConfig1;

    class MockX509CertificateAuthenticator extends X509CertificateAuthenticator {

        @Override
        protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext)
                throws AuthenticationFailedException {
            processAuthenticationResponse(httpServletRequest, httpServletResponse, authenticationContext);

        }

        @Override
        protected AuthenticatorConfig getAuthenticatorConfig() {
            return authenticatorConfig1;
        }
    }

    @Test(dataProvider = "provideX509Certificates")
    public void testProcessAuthenticationResponse(X509Certificate[] certificateArray, Object object1, Object object2,
            boolean exceptionShouldThrown, String exceptionMessage

    ) throws Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        AuthenticatorConfig authenticatorConfig = (AuthenticatorConfig) object1;
        authenticatorConfig1 = authenticatorConfig;
        when(mockRequest.getAttribute(X509CertificateConstants.X_509_CERTIFICATE)).thenReturn(certificateArray);
        X509CertificateAuthenticator x509CertificateAuthenticator = new MockX509CertificateAuthenticator();
        X509CertificateAuthenticator spy = PowerMockito.spy(x509CertificateAuthenticator);
        SequenceConfig sequenceConfig = (SequenceConfig) object2;
        authenticationContext.setSequenceConfig(sequenceConfig);
        doReturn(authenticatorConfig).when(spy, "getAuthenticatorConfig");
        mockStatic(X509CertificateUtil.class);
        when(X509CertificateUtil
                .validateCertificate(Matchers.anyString(), Matchers.any(AuthenticationContext.class), any(byte[].class),
                        Matchers.anyBoolean())).thenReturn(true);
        mockStatic(IdentityUtil.class);
        when(X509CertificateUtil
                .isAccountLock(Matchers.any(AuthenticatedUser.class))).thenReturn(false);
        when(X509CertificateUtil
                .isAccountDisabled(Matchers.any(AuthenticatedUser.class))).thenReturn(false);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");
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
