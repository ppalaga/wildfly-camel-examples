/*
 * #%L
 * Wildfly Camel :: Testsuite
 * %%
 * Copyright (C) 2013 - 2017 RedHat
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.wildfly.camel.test.cxf;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.net.ssl.SSLHandshakeException;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.net.ssl.*;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.security.Constants;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.camel.test.common.ServerReload;
import org.wildfly.camel.test.common.UserManager;
import org.wildfly.camel.test.common.WildFlyCli;
import org.wildfly.camel.test.common.http.HttpRequest;
import org.wildfly.camel.test.common.http.HttpRequest.HttpResponse;
import org.wildfly.camel.test.common.utils.DMRUtils;

@RunAsClient
@RunWith(Arquillian.class)
@ServerSetup(CxfWsCdiSecureExampleTest.ServerSecuritySetup.class)
public class CxfWsCdiSecureExampleTest {

    private static final Path WILDFLY_HOME = Paths.get(System.getProperty("jboss.home"));
    private static final Path BASEDIR = Paths.get(System.getProperty("project.basedir"));

    private static final String HTTPS_HOST = "https://localhost:8443";
    private static final String ENDPOINT_ADDRESS = "http://localhost:8080/example-camel-cxf-jaxws-cdi-secure/cxf/";
    private static final String WS_ENDPOINT_ADDRESS = "https://localhost:8443/webservices/greeting-secure-cdi";

    private static final String WS_MESSAGE_TEMPLATE = "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">" //
            + "<Body>" //
            + "<greet xmlns=\"http://jaxws.cxf.examples.camel.wildfly.org/\">" //
            + "<message xmlns=\"\">%s</message>" //
            + "<name xmlns=\"\">%s</name>" //
            + "</greet>" //
            + "</Body>" //
            + "</Envelope>";
    private static final String TRUSTSTORE_PASSWORD = "password";
    private static final String APPLICATION_USER = "CN=localhost";
    private static final String APPLICATION_PASSWORD = "testPassword1+";
    private static final String APPLICATION_ROLE = "testRole";

    static class ServerSecuritySetup implements ServerSetupTask {


        private static final String TRUSTSTORE_PATH = "${jboss.home.dir}/standalone/configuration/application.keystore";

        private static final String ADDRESS_SYSTEM_PROPERTY_TRUST_STORE_PASSWORD = "system-property=javax.net.ssl.trustStorePassword";
        private static final String ADDRESS_SYSTEM_PROPERTY_TRUST_STORE = "system-property=javax.net.ssl.trustStore";

        private static final String ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CERTIFICATE_TRUST_DOMAIN = "subsystem=security/security-domain=certificate-trust-domain";
        private static final String ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CERTIFICATE_TRUST_DOMAIN_JSSE_CLASSIC = ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CERTIFICATE_TRUST_DOMAIN
                + "/jsse=classic";
        private static final String ADDRESS_ATTRIBUTE_TRUSTSTORE = "truststore";

        private static final String ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CLIENT_CERT = "subsystem=security/security-domain=client-cert";
        private static final String ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CLIENT_CERT_AUTH_CLASSIC = ADDRESS_SUBSYSTEM_SECURITY_SECURITY_DOMAIN_CLIENT_CERT
                + "/authentication=classic";

        private static final String ADDRESS_SUBSYSTEM_UNDERTOW_HTTPS_LISTENER = "subsystem=undertow/server=default-server/https-listener=https";

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            // Make WildFly generate a keystore
            HttpRequest.post(HTTPS_HOST).getResponse();

            UserManager.addApplicationUser(APPLICATION_USER, APPLICATION_PASSWORD);
            UserManager.addRoleToApplicationUser(APPLICATION_USER, APPLICATION_ROLE);

            new WildFlyCli(WILDFLY_HOME)
                    .run(BASEDIR.resolve(
                            "../camel-cxf-jaxws-cdi-secure/src/main/resources/cli/configure-tls-security-elytron.cli"))
                    .assertSuccess();
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            // TODO run the cleanup script
            // new
            // WildFlyCli(WILDFLY_HOME).run(BASEDIR.resolve("../camel-cxf-jaxws-cdi-secure/src/main/resources/cli/remove-tls-security.cli")).assertSuccess();

            UserManager.removeApplicationUser(APPLICATION_USER);
            UserManager.revokeRoleFromApplicationUser(APPLICATION_USER, APPLICATION_ROLE);
        }

    }

    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap.createFromZipFile(WebArchive.class,
                new File("target/examples/example-camel-cxf-jaxws-cdi-secure.war"));
    }

//    @Test
//    public void testSecureCxfSoapRoute() throws Exception {
//        HttpResponse result = HttpRequest.post(ENDPOINT_ADDRESS)
//                .header("Content-Type", "application/x-www-form-urlencoded").content("message=Hello&name=Kermit")
//                .getResponse();
//
//        Assert.assertTrue(result.getBody().contains("Hello Kermit"));
//    }

    private static SSLConnectionSocketFactory createSocketFactory() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        SSLContext sslcontext = SSLContexts.custom()//
                .loadTrustMaterial(
                        WILDFLY_HOME.resolve("standalone/configuration/application.keystore").toFile(),
                        TRUSTSTORE_PASSWORD.toCharArray(), //
                        TrustSelfSignedStrategy.INSTANCE)//
                .build();
        return new SSLConnectionSocketFactory(sslcontext,
                new HostnameVerifier() {
                    @Override
                    public boolean verify(final String s, final SSLSession sslSession) {
                        return "localhost".equals(s);
                    }
                });
    }

//    @Test
//    public void indexJsp() throws Exception {
//
//        try (CloseableHttpClient httpclient = HttpClients.custom()
//                .setSSLSocketFactory(createSocketFactory())
//                .build()) {
//            HttpGet request = new HttpGet(ENDPOINT_ADDRESS);
//
//            String auth = APPLICATION_USER + ":" + APPLICATION_PASSWORD;
//            String authHeader = "Basic " + Base64.getEncoder().encodeToString(auth.getBytes(Charset.forName("ISO-8859-1")));
//            request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
//
//            try (CloseableHttpResponse response = httpclient.execute(request)) {
//                Assert.assertEquals(200, response.getStatusLine().getStatusCode());
//            }
//        }
//
//    }


    @Test
    public void greetBasic() throws Exception {

        try (CloseableHttpClient httpclient = HttpClients.custom()
                .setSSLSocketFactory(createSocketFactory())
                .build()) {
            HttpPost request = new HttpPost(WS_ENDPOINT_ADDRESS);
            request.setHeader("Content-Type", "text/xml");
            request.setHeader("soapaction", "\"urn:greet\"");

            String auth = APPLICATION_USER + ":" + APPLICATION_PASSWORD;
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(auth.getBytes(Charset.forName("ISO-8859-1")));
            request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            request.setEntity(new StringEntity(String.format(WS_MESSAGE_TEMPLATE, "Hi", "Joe"), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpclient.execute(request)) {
                Assert.assertEquals(200, response.getStatusLine().getStatusCode());

                HttpEntity entity = response.getEntity();
                String body = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                Assert.assertTrue(body.contains("Hi Joe"));
            }
        }

    }

    @Test
    public void greetAnonymous() throws Exception {

        try (CloseableHttpClient httpclient = HttpClients.custom()
                .setSSLSocketFactory(createSocketFactory())
                .build()) {
            HttpPost request = new HttpPost(WS_ENDPOINT_ADDRESS);
            request.setHeader("Content-Type", "text/xml");
            request.setHeader("soapaction", "\"urn:greet\"");

            request.setEntity(new StringEntity(String.format(WS_MESSAGE_TEMPLATE, "Hi", "Joe"), StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpclient.execute(request)) {
                Assert.assertEquals(401, response.getStatusLine().getStatusCode());
            }
        }

    }


}
