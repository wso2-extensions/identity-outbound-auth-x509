package org.wso2.carbon.sample.servlet;/*
* Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class X509CertificateAssociation {

    private static Log log = LogFactory.getLog(X509CertificateAssociation.class);

    protected void associateFederatedIdToLocalUsername(HttpServletRequest request, AuthenticationContext context
            , AuthenticatedUser authenticatedUser)
            throws UserProfileException {
        String authenticatedLocalUsername = request.getParameter(X509CertificateConstants.USER_NAME);
        StepConfig stepConfig = null;

        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName = FrameworkConstants.LOCAL_IDP_NAME;
                        String originalExternalIdpSubjectValueForThisStep =
                                authenticatedUser.getAuthenticatedSubjectIdentifier();
                        idpName = context.getExternalIdP().getIdPName();
                        stepConfig.setAuthenticatedIdP(idpName);
                        associateID(idpName, originalExternalIdpSubjectValueForThisStep, authenticatedLocalUsername);
                        stepConfig.setAuthenticatedUser(authenticatedUser);
                        context.getSequenceConfig().getStepMap().put(i, stepConfig);
                    } catch (UserProfileException e) {
                        throw new UserProfileException("Unable to continue with the federated ID ("
                                + authenticatedUser.getAuthenticatedSubjectIdentifier() + "): " + e.getMessage(), e);
                    }
                    break;
                }
            }
        }
    }

    protected String getAssociatedUsername(AuthenticationContext context, String userId) throws UserProfileException {
        StepConfig stepConfig = null;
        String associatedUserName = "";
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName = FrameworkConstants.LOCAL_IDP_NAME;
                        idpName = context.getExternalIdP().getIdPName();
                        stepConfig.setAuthenticatedIdP(idpName);
                        associatedUserName = getNameAssociatedWith(userId);
                    } catch (UserProfileException e) {
                        throw new UserProfileException("Unable to get the username associated with " +
                                "the federated ID (" + userId + "): " + e.getMessage(), e);
                    }
                    break;
                }
            }
        }
        return associatedUserName;
    }

    public String getNameAssociatedWith(String associatedID) throws UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql;
        String username;
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        try {
            sql = "SELECT DOMAIN_NAME, USER_NAME FROM IDN_X509_KEY WHERE TENANT_ID = ? AND IDP_PUBLIC_KEY = ?";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, associatedID);
            ResultSet resultSet = prepStmt.executeQuery();
            connection.commit();
            if(resultSet.next()) {
                String e = resultSet.getString(1);
                username = resultSet.getString(2);
                if(!"PRIMARY".equals(e)) {
                    username = e + "/" + username;
                }

                String var10 = username;
                return var10;
            }
        } catch (SQLException var14) {
            log.error("Error occurred while getting associated name", var14);
            throw new UserProfileException("Error occurred while getting associated name", var14);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, (ResultSet)null, prepStmt);
        }

        return null;
    }

    public String getName() {
        return "x509Certificate";
    }

    protected void associateID(String idpID, String associatedID, String userName) throws UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql = null;
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        String domainName = getDomainName(tenantAwareUsername);
        tenantAwareUsername = getUsernameWithoutDomain(tenantAwareUsername);
        try {
            sql = "INSERT INTO IDN_ASSOCIATED_ID (TENANT_ID, IDP_ID, IDP_USER_ID, DOMAIN_NAME, USER_NAME) VALUES " +
                    "(? , (SELECT ID FROM IDP WHERE NAME = ? AND TENANT_ID = ? ), ? , ?, ?)";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, associatedID);
            prepStmt.setString(5, domainName);
            prepStmt.setString(6, tenantAwareUsername);
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            log.error("Error occurred while persisting the federated user ID", e);
            throw new UserProfileException("Error occurred while persisting the federated user ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, (ResultSet) null, prepStmt);
        }
    }

    private static String getDomainName(String username) {
        int index = username.indexOf("/");
        return index < 0 ? "PRIMARY" : username.substring(0, index);
    }

    private static String getUsernameWithoutDomain(String username) {
        int index = username.indexOf("/");
        return index < 0 ? username : username.substring(index + 1, username.length());
    }

    protected AuthenticatedUser getFederateAuthenticatedUser(AuthenticationContext context, String authenticatedUserId)
            throws ApplicationAuthenticatorException {
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        authenticatedUser.setUserName(authenticatedUserId);
        if (log.isDebugEnabled()) {
            log.debug("The authenticated subject identifier :" + authenticatedUser.getAuthenticatedSubjectIdentifier());
        }
        return authenticatedUser;
    }
}
