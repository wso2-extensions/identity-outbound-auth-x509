/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class ServletURLUtils {
    public static final String IDM_PROPERTIES_FILE = "identity-mgt.properties";
    public static final String USER_AUTH_ENDPOINT = "x509-certificate-servlet";
    public static final String DEFAULT_AUTH_ENDPOINT = "https://localhost:8443/x509-certificate-servlet";

    private static Properties properties = new Properties();
    private static final Log log = LogFactory.getLog(ServletURLUtils.class);

    static {
        loadProperties();
    }

    private ServletURLUtils() {
    }

    /**
     * loading the identity-mgt.properties file.
     */
    public static void loadProperties() {
        FileInputStream fileInputStream = null;
        String configPath = CarbonUtils.getCarbonConfigDirPath() + File.separator + "identity" + File.separator;
        try {
            configPath = configPath + IDM_PROPERTIES_FILE;
            fileInputStream = new FileInputStream(new File(configPath));
            properties.load(fileInputStream);
        } catch (FileNotFoundException e) {
            throw new RuntimeException("identity-mgt.properties file not found in " + configPath, e);
        } catch (IOException e) {
            throw new RuntimeException("identity-mgt.properties file reading error from " + configPath, e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (Exception e) {
                    log.error("Error occurred while closing stream :" + e);
                }
            }
        }
    }

    /**
     * Get the user endpoint Url.
     */
    public static String getUserAuthEndpoint() {
        if (properties.get(USER_AUTH_ENDPOINT) != null) {
            return String.valueOf(properties.get(USER_AUTH_ENDPOINT));
        } else {
            return String.valueOf(DEFAULT_AUTH_ENDPOINT);
        }
    }
}