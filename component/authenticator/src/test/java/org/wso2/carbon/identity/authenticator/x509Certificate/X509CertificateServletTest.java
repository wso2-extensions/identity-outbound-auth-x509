/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.x509Certificate;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for X509CertificateServlet.
 */
public class X509CertificateServletTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private ServiceURLBuilder mockServiceURLBuilder;

    @Mock
    private ServiceURL mockServiceURL;

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    private X509CertificateServlet servlet;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMock;
    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<FrameworkUtils> frameworkUtilsMock;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        servlet = new X509CertificateServlet();
        serviceURLBuilderMock = mockStatic(ServiceURLBuilder.class);
        identityUtilMock = mockStatic(IdentityUtil.class);
        frameworkUtilsMock = mockStatic(FrameworkUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        serviceURLBuilderMock.close();
        identityUtilMock.close();
        frameworkUtilsMock.close();
    }

    @DataProvider(name = "hostnameConfigProvider")
    public Object[][] hostnameConfigProvider() {

        return new Object[][] {
            // useInternalHostname, expectedURL, sessionDataKey.
            { "true", "https://internal.wso2.com/commonauth", "test-session-key-internal" },
            { "false", "https://public.wso2.com/commonauth", "test-session-key-public" }
        };
    }

    @Test(dataProvider = "hostnameConfigProvider")
    public void testDoPostWithHostnameConfiguration(String useInternalHostname, String expectedURL,
                                                    String sessionDataKey) throws Exception {

        when(mockRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY)).thenReturn(sessionDataKey);
        identityUtilMock.when(() -> IdentityUtil.getProperty(X509CertificateConstants.USE_INTERNAL_HOSTNAME_FOR_REDIRECT))
                .thenReturn(useInternalHostname);

        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(X509CertificateConstants.COMMON_AUTH))
                .thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);

        boolean isInternal = Boolean.parseBoolean(useInternalHostname);
        if (isInternal) {
            when(mockServiceURL.getAbsoluteInternalURL()).thenReturn(expectedURL);
        } else {
            when(mockServiceURL.getAbsolutePublicURL()).thenReturn(expectedURL);
        }

        frameworkUtilsMock.when(() -> FrameworkUtils.getContextData(mockRequest))
                .thenReturn(mockAuthenticationContext);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("context-id");

        servlet.doPost(mockRequest, mockResponse);
        String expectedRedirectURL = expectedURL + "?sessionDataKey=" + sessionDataKey + "&success=true";
        verify(mockResponse).sendRedirect(expectedRedirectURL);

        if (isInternal) {
            verify(mockServiceURL).getAbsoluteInternalURL();
        } else {
            verify(mockServiceURL).getAbsolutePublicURL();
        }
    }
}
