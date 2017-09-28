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

import javax.servlet.http.HttpSession;

/**
 * Handle sessions.
 */
public class X509CertificateSessionHolder {
    private final ThreadLocal<HttpSession> threadLocal = new ThreadLocal<>();

    /**
     * Set session.
     *
     * @param session http session
     */
    public void set(HttpSession session) {
        threadLocal.set(session);
    }

    /**
     * Get session.
     *
     * @return http session
     */
    public HttpSession get() {
        return threadLocal.get();
    }

    /**
     * Remove session.
     */
    public void remove() {
        threadLocal.remove();
    }
}