package org.wso2.carbon.identity.authenticator.x509cert.valve.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;

public class X509ServerConfiguration {

    private static Log log = LogFactory.getLog(X509ServerConfiguration.class);
    private static X509ServerConfiguration instance;
    private static final String CONFIG_ELEM_X509 = "X509";

    private String x509requestHeader = "X-SSL-CERT";

    private X509ServerConfiguration() {

        buildOAuthServerConfiguration();
    }

    public static X509ServerConfiguration getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (X509ServerConfiguration.class) {
                if (instance == null) {
                    instance = new X509ServerConfiguration();
                }
            }
        }
        return instance;
    }

    /**
     * @return name of the X509 request header
     */
    public String getX509requestHeader() {

        return x509requestHeader;
    }

    private void buildOAuthServerConfiguration() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement x509Elem = configParser.getConfigElement(CONFIG_ELEM_X509);

        if (x509Elem == null) {
            warnOnFaultyConfiguration("X509 element is not available.");
            return;
        }

        // Read X509 Configurations.
        parseX509ServerValidators(x509Elem);
    }

    private void parseX509ServerValidators(OMElement x509Elem) {

        // Get the configured name of the X509Request header.
        if (x509Elem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.X509_REQUEST_HEADER)) != null) {
            x509requestHeader =
                    x509Elem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.X509_REQUEST_HEADER))
                            .getText().trim();
        }
    }

    private void warnOnFaultyConfiguration(String logMsg) {

        log.warn("Error in X509 Configuration. " + logMsg);
    }

    private QName getQNameWithIdentityNS(String localPart) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private class ConfigElements {

        // X509 Request header
        public static final String X509_REQUEST_HEADER = "X509RequestHeaderName";
    }
}
