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

package org.wso2.carbon.identity.x509Certificate.validation;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.registry.core.RegistryConstants.PATH_SEPARATOR;

public class CertificateValidationUtil {

    private static Log log = LogFactory.getLog(CertificateValidationUtil.class);

    public static List<RevocationValidator> loadValidatorConfig() throws CertificateValidationException {
        String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH;
        List<RevocationValidator> validators = new ArrayList<>();

        try {
            //get tenant registry for loading validator configurations
            Registry registry = getGovernanceRegistry();
            if (registry.resourceExists(validatorConfRegPath)) {
                Collection collection = (Collection) registry.get(validatorConfRegPath);
                if (collection != null) {
                    String[] children = collection.getChildren();
                    for (String child : children) {
                        Resource resource = registry.get(child);
                        Validator validator = resourceToValidatorObject(resource);
                        RevocationValidator revocationValidator;
                        try {
                            Class<?> clazz = Class.forName(validator.getName());
                            Constructor<?> constructor = clazz.getConstructor();
                            revocationValidator = (RevocationValidator) constructor.newInstance();
                        } catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException |
                                InstantiationException | IllegalAccessException e) {
                            continue;
                        }
                        revocationValidator.setEnable(validator.getEnabled());
                        revocationValidator.setPriority(validator.getPriority());
                        validators.add(revocationValidator);
                    }
                }
            }
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error while loading validator configurations from registry.", e);
        }
        return validators;
    }

    public static void addDefaultValidatorConfig() {
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        List<Validator> defaultValidatorConfig = getDefaultValidatorConfig();

        // iterate through the validator config list and write to the the registry
        for (Validator validator : defaultValidatorConfig) {
            String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH +
                    PATH_SEPARATOR + getNormalizedName(validator.getDisplayName());
            try {
                Registry registry = getGovernanceRegistry();
                if (!registry.resourceExists(validatorConfRegPath)) {
                    addValidatorConfigInRegistry(registry, validatorConfRegPath, validator);
                    if (log.isDebugEnabled()) {
                        String msg = "Validator configuration for %s is added to %s tenant registry.";
                        log.debug(String.format(msg, validator.getDisplayName(), tenantDomain));
                    }
                }
            } catch (RegistryException e) {
                log.error("Error while adding validator configurations in registry.", e);
            }
        }
    }

    public static List<Validator> getDefaultValidatorConfig() {
        String configFilePath = CarbonUtils.getCarbonConfigDirPath() + File.separator +
                X509CertificateValidationConstants.VALIDATOR_CONF_DIRECTORY + File.separator +
                X509CertificateValidationConstants.VALIDATOR_CONF_FILE;

        List<Validator> defaultValidatorConfig = new ArrayList<>();
        File configFile = new File(configFilePath);
        if (!configFile.exists()) {
            log.error("Certification validator Configuration File is not present at: " + configFilePath);
        }

        XMLStreamReader xmlStreamReader = null;
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(configFile);
            StAXOMBuilder builder = new StAXOMBuilder(inputStream);

            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement omElement = (OMElement) iterator.next();
                String name = omElement.getAttributeValue(
                        new QName(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
                String displayName = omElement.getAttributeValue(
                        new QName(X509CertificateValidationConstants.VALIDATOR_CONF_DISPLAY_NAME));
                String enable = omElement.getAttributeValue(
                        new QName(X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE));

                Map<String, String> validatorProperties = getValidatorProperties(omElement);
                String priority = validatorProperties.get(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY);

                Validator validator = new Validator();
                validator.setName(name);
                validator.setDisplayName(displayName);
                validator.setEnabled(Boolean.parseBoolean(enable));
                validator.setPriority(Integer.parseInt(priority));

                defaultValidatorConfig.add(validator);
            }
        } catch (XMLStreamException | FileNotFoundException e) {
            log.warn("Error while loading default validator configurations to the registry.", e);
        } finally {
            try {
                if (xmlStreamReader != null) {
                    xmlStreamReader.close();
                }
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (XMLStreamException e) {
                log.error("Error while closing XML stream", e);
            } catch (IOException e) {
                log.error("Error while closing input stream", e);
            }
        }

        return defaultValidatorConfig;
    }

    private static void addValidatorConfigInRegistry(Registry registry, String validatorConfRegPath, Validator validator)
            throws RegistryException {
        Resource resource = registry.newResource();
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_NAME, validator.getName());
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE,
                Boolean.toString(validator.getEnabled()));
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY,
                Integer.toString(validator.getPriority()));
        registry.put(validatorConfRegPath, resource);
    }

    private static Map<String, String> getValidatorProperties(OMElement validatorElement) {
        Map<String, String> validatorProperties = new HashMap<>();
        Iterator it = validatorElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            String elementName = element.getLocalName();
            String elementText = element.getText();
            if (StringUtils.equalsIgnoreCase(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY, elementName)) {
                validatorProperties.put(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY, elementText);
            }
        }
        return validatorProperties;
    }

    private static String getNormalizedName(String name) {
        if (StringUtils.isNotBlank(name)) {
            return name.replaceAll("\\s+", "").toLowerCase();
        }
        throw new IllegalArgumentException("Invalid validator name provided : " + name);
    }


    private static Registry getGovernanceRegistry() throws RegistryException {
        Registry registry;
        registry = CertValidationDataHolder.getRegistryService().getGovernanceSystemRegistry
                (CarbonContext.getThreadLocalCarbonContext().getTenantId());
        return registry;
    }

    private static Validator resourceToValidatorObject(Resource resource) {
        Validator validator = new Validator();
        validator.setName(resource.getProperty(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
        validator.setEnabled(Boolean.parseBoolean(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE)));
        validator.setPriority(Integer.parseInt(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY)));
        return validator;
    }
}
