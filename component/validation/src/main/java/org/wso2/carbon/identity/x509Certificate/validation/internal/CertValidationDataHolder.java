/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.x509Certificate.validation.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class CertValidationDataHolder {

    private static RegistryService registryService;
    private static RealmService realmService;
    private static CertValidationDataHolder instance = new CertValidationDataHolder();

    private CertValidationDataHolder() {
    }

    public static CertValidationDataHolder getInstance() {
        return instance;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService service) {
        registryService = service;
    }

    public void unsetRegistryService() {
        registryService = null;
    }

    public void setRealmService(RealmService realmService) {
        CertValidationDataHolder.realmService = realmService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void unsetRealmService() {
        realmService = null;
    }
}
