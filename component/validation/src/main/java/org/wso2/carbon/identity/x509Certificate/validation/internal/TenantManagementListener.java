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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class TenantManagementListener implements TenantMgtListener {

    private static final int EXEC_ORDER = 22;
    private static Log log = LogFactory.getLog(TenantManagementListener.class);

    public void onTenantCreate(TenantInfoBean tenantInfo) throws StratosException {
    }

    public void onTenantUpdate(TenantInfoBean tenantInfo) throws StratosException {
    }

    @Override
    public void onPreDelete(int tenantId) throws StratosException {
    }

    @Override
    public void onTenantDelete(int i) {
    }

    public void onTenantRename(int tenantId, String oldDomainName,
                               String newDomainName) throws StratosException {
    }

    public int getListenerOrder() {
        return EXEC_ORDER;
    }

    public void onTenantInitialActivation(int tenantId) throws StratosException {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext
                .getThreadLocalCarbonContext();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
        CertificateValidationUtil.addDefaultValidationConfigInRegistry(tenantDomain);
        PrivilegedCarbonContext.endTenantFlow();
    }

    public void onTenantActivation(int tenantId) throws StratosException {
    }

    public void onTenantDeactivation(int tenantId) throws StratosException {
    }

    public void onSubscriptionPlanChange(int tenentId, String oldPlan, String newPlan) throws StratosException {
    }

}

