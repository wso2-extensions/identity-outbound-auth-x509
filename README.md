## Welcome to the WSO2 Identity Server (IS) X509 Certificate authenticator.

WSO2 IS is one of the best Identity Servers, which enables you to offload your identity and user entitlement management burden totally from your application. It comes with many features, supports many industry standards and most importantly it allows you to extent it according to your security requirements. This repo contains Authenticators written to work with different third party systems.

With WSO2 IS, there are lot of provisioning capabilities available. There are 3 major concepts as Inbound, outbound provisioning and Just-In-Time provisioning. Inbound provisioning means , provisioning users and groups from an external system to IS. Outbound provisioning means , provisioning users from IS to other external systems. JIT provisioning means , once a user tries to login from an external IDP, a user can be created on the fly in IS with JIT. Repos under this account holds such components invlove in communicating with external systems.

## How to Configure X509 Certificate authenticator

Please follow the below steps to configure the X509 Certificate authenticator as the local authenticator to your application.

### STEP 1: Generate your own self-signed certificate.

1. Open a terminal and navigate to the directory where you want to keep the generated certificates `<CERTIFICATE_PATH>`.

2. Run the following command to generate you public certificate and the private key.
```sh
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out client.pem
```
_Note: Add appropriate values for the prompts and make sure to add the `username` of the created user as the `CN` field._

- Sample values for the prompts:
```sh
Country Name (2 letter code) [AU]:LK
State or Province Name (full name) [Some-State]:Western
Locality Name (eg, city) []:Colombo
Organization Name (eg, company) [Internet Widgits Pty Ltd]:WSO2
Organizational Unit Name (eg, section) []:IAM
Common Name (e.g. server FQDN or YOUR name) []:testuser
Email Address []:testuser@wso2.com
```

3. Run the following command to combine the generated private key and certificate to a PKCS12 format. This file is used to import the certificate to the browser.
```sh
openssl pkcs12 -export -in client.pem -inkey key.pem -out client.p12
```

4. Validate the PKCS12 file.
```sh
openssl pkcs12 -in client.p12 -noout -info
```

### STEP 2: Add the certificate to the Identity Server truststore and to your browser certificate list.

1. Import the certificate to the truststore.
```sh
keytool -importcert -alias localcrt -file client.pem -keystore <IS_HOME>/repository/resources/security/client-truststore.jks -storepass wso2carbon -noprompt
```

2. To add the certificate to your browser certificate list, open the browser and goto preferences > privacy > certificate > view certificate > import and choose the PKCS12 file created.
_Note: The browser certificate storage location may vary depending on the browser. The above configuration is valid for Firefox browser._

3. Restart the browser.

### STEP 3: Configure the Identity Server to use the X509 Certificate authenticator.

1. Download the X509 Certificate authenticator from the [WSO2 connector Store](https://store.wso2.com/store/assets/isconnector/details/59dd58ed-8335-476e-8ff6-069fc3620104).
2. Copy the downloaded JAR file into the <IS_HOME>/repository/components/dropins directory.
3. Open the <IS_HOME>/repository/conf/deployment.toml file and add the following authenticator configuration under
    the [authentication.authenticator.x509_certificate] configuration. (Replace the {carbon:host} and {carbon:port} with
    your own values.)
```toml
[authentication.authenticator.x509_certificate.parameters]
AuthenticationEndpoint="https://{carbon:host}:{carbon:port}/x509-certificate-servlet"
username="CN"
```
4. Restart the server.

### STEP 4: Create a Service provider and configure it to use the X509 Certificate authenticator as the local inbound authenticator.

1. Log in to the management console using your admin credentials.
2. Click Add under Service Providers.
3. Enter a name for the service provider in the Service Provider Name text box and click Register.
4. Expand Inbound Authentication Configuration and click SAML2 Web SSO Configuration.
5. Add the issuer name and the assertion consumer URL.
6. Select `Enable Attribute Profile` and `Include Attributes in the Response Always`.
7. Click Update.
8. Expand Local & Outbound Authentication Configuration and click Advanced Configuration.
9. Select Local Authenticators and then select the X509 Certificate authenticator from the drop-down list.
10. Click Update.

### STEP 5: Create a user.

1. Goto Identity > Users and Roles > Add > Add New User.
2. Enter the username and password.
3. Click Finish.
4. Click on the `User Profile` user you created.
5. Fill the email address field and click Update. (Fill any other fields which are required by default)

### STEP 6: Disable certificate validation in the Identity Server.

In product versions before WSO2 Identity Server 5.7.0, the CRL-and-OCSP-based certificate validations were disabled by 
default. With WSO2 Identity Server 5.7.0, CAs could be added to a truststore and get them verified through certificate 
validation. To complement this, CRL-and-OCSP-based certificate validations were enabled by default. Enabling 
certificate validation without adding the CAs to the truststore may cause errors.

Disable certificate validation if you are using WSO2 Identity Server 5.7.0 and do not require verifying CAs through 
certificate validation.

1. Goto the management console > Registry > Browse.
2. Browse for the following path: `/_system/governance/repository/security/certificate/validator/ocspvalidator`.
3. Expand the properties and set the value of the property named `enable` to `false` and save.
4. Do the same with the path `/_system/governance/repository/security/certificate/validator/crlvalidator` as well.


### Try it
1. Log in to your client application.
2. Click on the login button.
3. Select the certificate you added to the browser certificate list.
4. You will be logged in to the client application.

## Configure Server to Allow Multiple Login Identifiers

This feature is available for the following connector versions
- 2.0.25 and above for 2.0.x versions.
- 3.1.10 and above for 3.1.x versions.

Following configuration changes are required to enable this feature.

1. Open the `<IS_HOME>/repository/conf/deployment.toml` file and add the following configuration.
   (Replace the {carbon:host} and {carbon:port} with your own values.)
```toml
[authentication.authenticator.x509_certificate.parameters]
AuthenticationEndpoint="https://{carbon:host}:{carbon:port}/x509-certificate-servlet"
LoginClaimURIs="http://wso2.org/claims/emailaddress"
SearchAllUserStores="true"
```

_Note: Username claim URI need not to be added to the LoginClaimURIs property, as it is added by default._

2. Restart the server.
3. Generate your self-signed certificate with the `email address` as the `CN` field following the same as above step 1.
4. Add the certificate to the Identity Server truststore and to your browser certificate list using the step 2 in the above section.
5. Log in to the client application and select the new certificate you added to the browser certificate list.
6. You will be logged in to the client application.

## How You Can Contribute

You can create a third party connector and publish in WSO2 Store.

https://docs.wso2.com/display/ISCONNECTORS/Creating+a+Third+Party+Authenticator+or+Connector+and+Publishing+in+WSO2+Store