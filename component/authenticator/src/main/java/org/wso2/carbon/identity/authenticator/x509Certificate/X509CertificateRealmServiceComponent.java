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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.carbon.identity.authentication.internal.X509CertificateRealmServiceComponent" immediate="true"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"  unbind="unsetRealmService"
 */
public class X509CertificateRealmServiceComponent {

    private static Log log = LogFactory.getLog(X509CertificateRealmServiceComponent.class);
    private static RealmService realmService = null;

    /**
     * Get realm service.
     *
     * @return realm service
     */
    public static RealmService getRealmService() {
        return realmService;
    }

    /**
     * Set realm service.
     *
     * @param realmService realm service
     */
    protected void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    /**
     * Activate componentContext.
     *
     * @param componentContext component context
     */
    protected void activate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("Activating X509CertificateRealmServiceComponent ");
        }
    }

    /**
     * Deactivating componentContext.
     *
     * @param componentContext component context
     */
    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("Deactivating X509CertificateRealmServiceComponent ");
        }
    }

    /**
     * Unset realm service.
     *
     * @param realmService realm service
     */
    protected void unsetRealmService(RealmService realmService) {
        this.realmService = null;
    }
}