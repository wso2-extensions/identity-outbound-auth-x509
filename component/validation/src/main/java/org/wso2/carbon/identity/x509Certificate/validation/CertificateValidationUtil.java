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
import org.apache.axiom.om.util.*;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.*;
import org.apache.axiom.om.util.Base64;

import static org.wso2.carbon.registry.core.RegistryConstants.PATH_SEPARATOR;

public class CertificateValidationUtil {

    private static Log log = LogFactory.getLog(CertificateValidationUtil.class);
    private static final String BC = "BC";

    /**
     * ********************************************
     * Util methods for Validator Configurations
     * ********************************************
     */
    public static void addDefaultValidationConfigInRegistry(String tenantDomain) {
        String configFilePath = CarbonUtils.getCarbonConfigDirPath() + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_DIRECTORY + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_FILE;

        if (tenantDomain == null) {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        }

        File configFile = new File(configFilePath);
        if (!configFile.exists()) {
            log.error("Certification validation Configuration File is not present at: " + configFilePath);
            return;
        }

        XMLStreamReader xmlStreamReader = null;
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(configFile);
            StAXOMBuilder builder = new StAXOMBuilder(inputStream);

            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement childElement = (OMElement) iterator.next();
                if (childElement.getLocalName().equals(X509CertificateValidationConstants.VALIDATOR_CONF)) {
                    addDefaultValidatorConfig(childElement, tenantDomain);
                } else if(childElement.getLocalName().equals(X509CertificateValidationConstants.TRUSTSTORE_CONF)) {
                    addDefaultCACertificates(childElement, tenantDomain);
                }
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
    }

    public static List<RevocationValidator> loadValidatorConfigFromRegistry() throws CertificateValidationException {
        if(log.isDebugEnabled()) {
            log.debug("Loading X509 certificate validator configurations from registry.");
        }
        String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH;
        List<RevocationValidator> validators = new ArrayList<>();

        try {
            //get tenant registry for loading validator configurations
            Registry registry = getGovernanceRegistry(
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
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
                        revocationValidator.setFullChainValidation(validator.getFullChainValidationEnabled());
                        revocationValidator.setRetryCount(validator.getRetryCount());
                        validators.add(revocationValidator);
                    }
                }
            }
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error while loading validator configurations from registry.", e);
        }
        return validators;
    }

    /**
     * ****************************************
     * Util methods for CA Cert Configuration
     * ****************************************
     */
    private static void addDefaultCACertificates(OMElement trustStoresElement, String tenantDomain) {
        try {
            Iterator trustStoreIterator = trustStoresElement.getChildElements();
            Registry registry = getGovernanceRegistry(tenantDomain);
            List<X509Certificate> trustedCertificates = new ArrayList<>();

            while (trustStoreIterator.hasNext()) {
                OMElement trustStoreElement = (OMElement) trustStoreIterator.next();
                String trustStoreFile = trustStoreElement.getAttributeValue(
                        new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_FILE));
                String trustStorePassword = trustStoreElement.getAttributeValue(
                        new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_PASSWORD));

                KeyStore keyStore = CertificateValidationUtil.loadKeyStoreFromFile(trustStoreFile, trustStorePassword, null);
                try {
                    trustedCertificates.addAll(CertificateValidationUtil.exportCertificateChainFromKeyStore(keyStore));
                } catch (KeyStoreException e) {
                    log.error("Error while exporting certificate chain from trust store.", e);
                }
            }

            for(X509Certificate certificate :  trustedCertificates) {
                String caCertRegPath = X509CertificateValidationConstants.CA_CERT_REG_PATH +
                        PATH_SEPARATOR +
                        URLEncoder.encode(getNormalizedName(certificate.getSubjectDN().getName()), "UTF-8").
                                replaceAll("%", ":") + PATH_SEPARATOR +
                        getNormalizedName(certificate.getSerialNumber().toString());

                if (!registry.resourceExists(caCertRegPath)) {
                    addDefaultCACertificateInRegistry(registry, caCertRegPath, certificate);
                }
            }

        } catch (RegistryException | UnsupportedEncodingException | CertificateValidationException e) {
            log.error("Error while adding validator configurations in registry.", e);
        }
    }

    public static List<CACertificate> loadCaCertsFromRegistry(X509Certificate peerCertificate)
            throws CertificateValidationException {

        List<CACertificate> caCertificateList = new ArrayList<>();
        try {
            String caRegPath = X509CertificateValidationConstants.CA_CERT_REG_PATH +
                    PATH_SEPARATOR + URLEncoder.encode(getNormalizedName(peerCertificate.getIssuerDN().getName()), "UTF-8").
                    replaceAll("%", ":");

            //get tenant registry for loading validator configurations
            Registry registry = getGovernanceRegistry(
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            if (registry.resourceExists(caRegPath)) {
                Collection collection = (Collection) registry.get(caRegPath);
                if (collection != null) {
                    String[] children = collection.getChildren();
                    for (String child : children) {
                        Resource resource = registry.get(child);
                        CACertificate caCertificate = resourceToCACertObject(resource);
                        caCertificateList.add(caCertificate);
                    }
                }
            }
        } catch (RegistryException | UnsupportedEncodingException e) {
            throw new CertificateValidationException("Error while loading validator configurations from registry.", e);
        }
        return caCertificateList;
    }


    /**
     * **********************************
     * Util Methods for CRL Validation
     * **********************************
     */
    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    public static List<String> getCrlDistributionPoints(X509Certificate cert)
            throws CertificateValidationException {
        List<String> crlUrls = new ArrayList<>();

        //Gets the DER-encoded OCTET string for the extension value for CRLDistributionPoints
        byte[] crlDPExtensionValue = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        if (crlDPExtensionValue == null) {
            log.error("Certificate doesn't have CRL Distribution points");
            return crlUrls;
        }
        //crlDPExtensionValue is encoded in ASN.1 format.
        ASN1InputStream asn1In = new ASN1InputStream(crlDPExtensionValue);
        //DER (Distinguished Encoding Rules) is one of ASN.1 encoding rules defined in ITU-T X.690, 2002, specification.
        //ASN.1 encoding rules can be used to encode any data object into a binary file. Read the object in octets.
        CRLDistPoint distPoint;
        try {
            DEROctetString crlDEROctetString = (DEROctetString) asn1In.readObject();
            //Get Input stream in octets
            ASN1InputStream asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets());
            ASN1Primitive crlDERObject = asn1InOctets.readObject();
            distPoint = CRLDistPoint.getInstance(crlDERObject);
        } catch (IOException e) {
            throw new CertificateValidationException("Cannot read certificate to get CRL urls", e);
        }

        //Loop through ASN1Encodable DistributionPoints
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            //get ASN1Encodable DistributionPointName
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                //Create ASN1Encodable General Names
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for a URI
                //todo: May be able to check for OCSP url specifically.
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        //DERIA5String contains an ascii string.
                        //A IA5String is a restricted character string type in the ASN.1 notation
                        String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);
                    }
                }
            }
        }
        if (crlUrls.isEmpty()) {
            throw new CertificateValidationException("Cant get CRL urls from certificate");
        }
        return crlUrls;
    }


    /**
     * **************************************
     * Util Methods for OCSP Validation
     * **************************************
     */

    public static X509Certificate loadCaCertFromTrustStore(X509Certificate peerCertificate)
            throws CertificateValidationException {
        X509Certificate caCertificate = null;
        String configFilePath = CarbonUtils.getCarbonConfigDirPath() + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_DIRECTORY + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_FILE;

        File configFile = new File(configFilePath);
        if (!configFile.exists()) {
            throw new CertificateValidationException("Certification validation Configuration File is not present at: "
                    + configFilePath);
        }

        XMLStreamReader xmlStreamReader = null;
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(configFile);
            StAXOMBuilder builder = new StAXOMBuilder(inputStream);

            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement childElement = (OMElement) iterator.next();
                if(childElement.getLocalName().equals(X509CertificateValidationConstants.TRUSTSTORE_CONF)) {
                    Iterator trustStoreIterator = childElement.getChildElements();
                    List<X509Certificate> trustedCertificates = new ArrayList<>();

                    while (trustStoreIterator.hasNext()) {
                        OMElement trustStoreElement = (OMElement) trustStoreIterator.next();
                        String trustStoreFile = trustStoreElement.getAttributeValue(
                                new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_FILE));
                        String trustStorePassword = trustStoreElement.getAttributeValue(
                                new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_PASSWORD));
                        String type = trustStoreElement.getAttributeValue(
                                new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_TYPE));

                        KeyStore keyStore = CertificateValidationUtil.loadKeyStoreFromFile(trustStoreFile,
                                trustStorePassword, type);
                        try {
                            trustedCertificates.addAll(CertificateValidationUtil.exportCertificateChainFromKeyStore
                                    (keyStore));
                        } catch (KeyStoreException e) {
                            throw new CertificateValidationException("Error when exporting CA certificates from " +
                                    "trust store");
                        }
                    }

                    for(X509Certificate certificate :  trustedCertificates) {
                        if(certificate.getSubjectX500Principal().equals(peerCertificate.getIssuerX500Principal())){
                            caCertificate = certificate;
                        }
                    }
                }
            }
        } catch (XMLStreamException | FileNotFoundException e) {
            log.warn("Error while loading default CA certificates from trust stores.", e);
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
        return caCertificate;

    }

    /**
     * Authority Information Access (AIA) is a non-critical extension in an X509 Certificate. This contains the
     * URL of the OCSP endpoint if one is available.
     * TODO: This might contain non OCSP urls as well. Handle this.
     *
     * @param cert is the certificate
     * @return a lit of URLs in AIA extension of the certificate which will hopefully contain an OCSP endpoint.
     * @throws CertificateValidationException
     *
     */
    public static List<String> getAIALocations(X509Certificate cert) throws CertificateValidationException {
        List<String> ocspUrlList = new ArrayList<String>();

        //Gets the DER-encoded OCTET string for the extension value for Authority information access Points
        byte[] aiaExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaExtensionValue == null) {
            log.error("Certificate Doesn't have Authority Information Access points");
            return ocspUrlList;
        }
        AuthorityInformationAccess authorityInformationAccess;

        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue)).readObject());
            authorityInformationAccess = AuthorityInformationAccess.getInstance(new ASN1InputStream(oct.getOctets()).readObject());
        } catch (IOException e) {
            throw new CertificateValidationException("Cannot read certificate to get OSCP urls", e);
        }

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {

            GeneralName gn = accessDescription.getAccessLocation();
            if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                DERIA5String str = DERIA5String.getInstance(gn.getName());
                String accessLocation = str.getString();
                ocspUrlList.add(accessLocation);
            }
        }
        if(ocspUrlList.isEmpty())
            throw new CertificateValidationException("Cant get OCSP urls from certificate");

        return ocspUrlList;
    }



    private static void addDefaultValidatorConfig(OMElement validatorsElement, String tenantDomain) {

        List<Validator> defaultValidatorConfig = getDefaultValidatorConfig(validatorsElement);

        // iterate through the validator config list and write to the the registry
        for (Validator validator : defaultValidatorConfig) {
            String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH +
                    PATH_SEPARATOR + getNormalizedName(validator.getDisplayName());
            try {
                Registry registry = getGovernanceRegistry(tenantDomain);
                if (!registry.resourceExists(validatorConfRegPath)) {
                    addValidatorConfigInRegistry(registry, validatorConfRegPath, validator);
                    if (log.isDebugEnabled()) {
                        String msg = "Validator configuration for %s is added to %s tenant registry.";
                        log.debug(String.format(msg, validator.getDisplayName(), tenantDomain));
                    }
                }
            } catch (RegistryException | CertificateValidationException e) {
                log.error("Error while adding validator configurations in registry.", e);
            }
        }
    }

    private static List<Validator> getDefaultValidatorConfig(OMElement validatorsElement) {
        List<Validator> defaultValidatorConfig = new ArrayList<>();
        Iterator validatorIterator = validatorsElement.getChildElements();
        while(validatorIterator.hasNext()) {
            OMElement validatorElement = (OMElement) validatorIterator.next();
            String name = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
            String displayName = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_DISPLAY_NAME));
            String enable = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE));

            Map<String, String> validatorProperties = getValidatorProperties(validatorElement);
            String priority = validatorProperties.get(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY);
            String fullChainValidation = validatorProperties.get(
                    X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION);
            String retryCount = validatorProperties.get(X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT);

            Validator validator = new Validator();
            validator.setName(name);
            validator.setDisplayName(displayName);
            validator.setEnabled(Boolean.parseBoolean(enable));
            validator.setPriority(Integer.parseInt(priority));
            validator.setFullChainValidationEnabled(Boolean.parseBoolean(fullChainValidation));
            validator.setRetryCount(Integer.parseInt(retryCount));

            defaultValidatorConfig.add(validator);
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
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION,
                Boolean.toString(validator.getFullChainValidationEnabled()));
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT,
                Integer.toString(validator.getRetryCount()));
        registry.put(validatorConfRegPath, resource);
    }

    private static Map<String, String> getValidatorProperties(OMElement validatorElement) {
        Map<String, String> validatorProperties = new HashMap<>();
        Iterator it = validatorElement.getChildElements();
        //read the properties in the validator element
        while (it.hasNext()) {
            OMElement validatorParamElement = (OMElement) it.next();
            if (validatorParamElement != null) {
                String attributeName = validatorParamElement.getAttributeValue(new QName(
                X509CertificateValidationConstants.VALIDATOR_CONF_ELEMENT_PROPERTY_NAME));
                String attributeValue = validatorParamElement.getText();
                validatorProperties.put(attributeName, attributeValue);
            }
        }
        return validatorProperties;
    }

    private static Validator resourceToValidatorObject(Resource resource) {
        Validator validator = new Validator();
        validator.setName(resource.getProperty(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
        validator.setEnabled(Boolean.parseBoolean(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE)));
        validator.setPriority(Integer.parseInt(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY)));
        validator.setFullChainValidationEnabled(Boolean.parseBoolean(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION)));
        validator.setRetryCount(Integer.parseInt(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT)));
        return validator;
    }

    private static CACertificate resourceToCACertObject(Resource resource) throws CertificateValidationException {
        List<String> crlUrls;
        List<String> ocspUrls;
        X509Certificate x509Certificate;
        try {
            String crlUrlReg = resource.getProperty(X509CertificateValidationConstants.CA_CERT_REG_CRL);
            String ocspUrlReg = resource.getProperty(X509CertificateValidationConstants.CA_CERT_REG_OCSP);
            crlUrls = Arrays.asList(crlUrlReg.split(
                    X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR));
            ocspUrls = Arrays.asList(ocspUrlReg.split(
                    X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR));
            byte[] regContent = (byte[]) resource.getContent();
            x509Certificate = decodeCertificate(new String(regContent));
        } catch (RegistryException | CertificateException e) {
            throw new CertificateValidationException("Error when converting registry resource content.");
        }
        return new CACertificate(crlUrls, ocspUrls, x509Certificate);
    }

    private static void addDefaultCACertificateInRegistry(Registry registry, String caCertRegPath,
                                                          X509Certificate certificate)
            throws CertificateValidationException {
        try {
            if (!registry.resourceExists(caCertRegPath)) {
                Resource resource = registry.newResource();
                List<String> crlUrls = getCrlDistributionPoints(certificate);
                StringBuilder crlUrlReg = new StringBuilder();
                if (CollectionUtils.isNotEmpty(crlUrls)) {
                    for (String crlUrl : crlUrls) {
                        crlUrlReg.append(crlUrl).append(X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR);
                    }
                }

                List<String> ocspUrls = getAIALocations(certificate);
                StringBuilder ocspUrlReg = new StringBuilder();
                if (CollectionUtils.isNotEmpty(ocspUrls)) {
                    for (String ocspUrl : ocspUrls) {
                        ocspUrlReg.append(ocspUrl).append(X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR);
                    }
                }
                resource.addProperty(X509CertificateValidationConstants.CA_CERT_REG_CRL, crlUrlReg.toString());
                resource.addProperty(X509CertificateValidationConstants.CA_CERT_REG_OCSP, ocspUrlReg.toString());
                resource.setContent(encodeCertificate(certificate));
                registry.put(caCertRegPath, resource);
            }
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error adding default ca certificate in registry.", e);
        } catch (CertificateException e) {
            throw new CertificateValidationException("Error encoding ca certificate to add in registry.", e);
        }
    }

    /**
     * Generic Util Methods
     */

    private static KeyStore loadKeyStoreFromFile(String keyStorePath, String password, String type) {
        if(type == null) {
            type = X509CertificateValidationConstants.TRUSTSTORE_CONF_TYPE_DEFAULT;
        }
        CarbonUtils.checkSecurity();
        String absolutePath = new File(keyStorePath).getAbsolutePath();
        FileInputStream inputStream = null;
        try {
            KeyStore store = KeyStore.getInstance(type);
            inputStream = new FileInputStream(absolutePath);
            store.load(inputStream, password.toCharArray());
            return store;
        } catch (Exception e) {
            String errorMsg = "Error loading the key store from the given location.";
            log.error(errorMsg);
            throw new SecurityException(errorMsg, e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.warn("Error when closing the input stream.", e);
            }
        }
    }

    private static List<X509Certificate> exportCertificateChainFromKeyStore(KeyStore keyStore) throws KeyStoreException {
        Enumeration<String> aliases =  keyStore.aliases();
        List<X509Certificate> certificates = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            certificates.add((X509Certificate) keyStore.getCertificate(alias));
        }
        return certificates;
    }

    private static String getNormalizedName(String name) {
        if (StringUtils.isNotBlank(name)) {
            return name.replaceAll("\\s+", "").toLowerCase();
            //~!@#;%^*+={}|<>,\\'\\\\"\\\\\\\\()[]
        }
        throw new IllegalArgumentException("Invalid validator name provided : " + name);
    }


    private static Registry getGovernanceRegistry(String tenantDomain) throws CertificateValidationException {
        Registry registry = null;
        try {
            registry = CertValidationDataHolder.getInstance().getRegistryService().getGovernanceSystemRegistry(
                    CertValidationDataHolder.getInstance().getRealmService().getTenantManager().getTenantId(tenantDomain));
        } catch (UserStoreException | RegistryException e) {
            throw new CertificateValidationException("Error while get tenant registry.", e);
        }
        return registry;
    }

/*    *//**
     * Converts a X509Certificate instance into a Base-64 encoded string (PEM format).
     *
     * @param x509Cert A X509 Certificate instance
     * @return PEM formatted String
     * @throws IOException
     *//*
    private static String convertX509CertToBase64PEMString(X509Certificate x509Cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (PEMWriter pw = new PEMWriter(sw)) {
            pw.writeObject(x509Cert);
        }
        return sw.toString();
    }

    private static String convertX509CertToBase64(X509Certificate x509Cert) throws IOException {
        StringWriter sw = new StringWriter();
        try {
            sw.write("-----BEGIN CERTIFICATE-----\n");
            sw.write(DatatypeConverter.printBase64Binary(x509Cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
            sw.write("\n-----END CERTIFICATE-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return sw.toString();
    }

    *//**
     * Converts a PEM formatted String to a X509Certificate instance.
     *
     * @param pem PEM formatted String
     * @return a X509Certificate instance
     * @throws CertificateException
     * @throws IOException
     *//*
    public static X509Certificate convertBase64PEMToX509Certificate(String pem) throws IOException {
        StringReader reader = new StringReader(pem);
        PEMReader pr = new PEMReader(reader);
        X509Certificate x509Cert = (X509Certificate)pr.readObject();
        return x509Cert;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateValidationException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateValidationException(e);
        }
        return certificate;
    }*/

    /**
     * Generate thumbprint of certificate
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws java.security.cert.CertificateException Error when decoding certificate
     */
    public static X509Certificate decodeCertificate(String encodedCert) throws CertificateException {

        if (encodedCert != null) {
            byte[] bytes = Base64.decode(encodedCert);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory
                    .generateCertificate(new ByteArrayInputStream(bytes));
            return cert;
        } else {
            String errorMsg = "Invalid encoded certificate: \'NULL\'";
            log.debug(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }

    /**
     * Generate thumbprint of certificate
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws java.security.cert.CertificateException Error when decoding certificate
     */
    public static String encodeCertificate(X509Certificate certificate) throws CertificateException {

        if (certificate != null) {
            return Base64.encode(certificate.getEncoded());
        } else {
            String errorMsg = "Invalid encoded certificate: \'NULL\'";
            log.debug(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }

}
