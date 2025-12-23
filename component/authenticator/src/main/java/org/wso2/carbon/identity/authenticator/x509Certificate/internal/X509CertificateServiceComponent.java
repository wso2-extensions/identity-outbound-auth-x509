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
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateAuthenticator;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

@Component(
        name = "osgi.servlet.dscomponent",
        immediate = true
)
public class X509CertificateServiceComponent {
    private static final Log log = LogFactory.getLog(X509CertificateServiceComponent.class);

    /**
     * Activate service.
     *
     * @param componentContext component context
     */
    @Activate
    protected void activate(ComponentContext componentContext) {
        X509CertificateAuthenticator authenticator = new X509CertificateAuthenticator();
        Hashtable<String, String> props = new Hashtable<>();
        componentContext.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), authenticator, props);

        log.debug("X509 Certificate Servlet activated successfully.");
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

    @Reference(
            name = "accountLockService",
            service = AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        X509CertificateDataHolder.getInstance().setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        X509CertificateDataHolder.getInstance().setAccountLockService(null);
    }

    @Reference(
            name = "osgi.user.realm.service.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the X509 authenticator bundle.");
        }
        X509CertificateDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the X509 authenticator bundle.");
        }
        X509CertificateDataHolder.getInstance().setRealmService(null);
    }
}
