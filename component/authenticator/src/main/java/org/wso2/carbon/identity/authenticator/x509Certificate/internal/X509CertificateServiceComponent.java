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
package org.wso2.carbon.identity.authenticator.x509Certificate.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.osgi.service.http.NamespaceException;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateAuthenticator;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateConstants;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateDataHolder;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateServlet;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.util.Hashtable;

/**
 * @scr.component name="osgi.servlet.dscomponent" immediate=true
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 */

public class X509CertificateServiceComponent {
    private static Log log = LogFactory.getLog(X509CertificateServiceComponent.class);

    /**
     * Activate service.
     *
     * @param componentContext component context
     */
    protected void activate(ComponentContext componentContext) {
        X509CertificateAuthenticator authenticator = new X509CertificateAuthenticator();
        Hashtable<String, String> props = new Hashtable<>();
        componentContext.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), authenticator, props);
        Servlet servlet = new ContextPathServletAdaptor(
                new X509CertificateServlet(), X509CertificateConstants.SERVLET_URL);
        try {
            X509CertificateDataHolder.getInstance().getHttpService()
                    .registerServlet(X509CertificateConstants.SERVLET_URL, servlet, null, null);
            log.info("X509 Certificate Servlet activated successfully..");
        } catch (NamespaceException | ServletException e) {
            throw new RuntimeException("Error when registering X509 Certificate Servlet via the HttpService.", e);
        }
    }

    /**
     * Deactivate service.
     *
     * @param componentContext component context
     */
    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("X509 Certificate Servlet is deactivated ");
        }
    }

    /**
     * Set httpservice.
     *
     * @param httpService http service
     */
    protected void setHttpService(HttpService httpService) {
        X509CertificateDataHolder.getInstance().setHttpService(httpService);
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the X509 Certificate Servlet");
        }
    }

    /**
     * Unset httpservice.
     *
     * @param httpService http service
     */
    protected void unsetHttpService(HttpService httpService) {
        X509CertificateDataHolder.getInstance().setHttpService(null);
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the X509 Certificate Servlet");
        }
    }
}
