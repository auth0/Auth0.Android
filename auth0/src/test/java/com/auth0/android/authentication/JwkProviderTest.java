package com.auth0.android.authentication;

import com.google.gson.JsonParseException;

import org.apache.tools.ant.filters.StringInputStream;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class JwkProviderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final String SAMPLE_JWKS_RS = "{" +
            "\"keys\": [{\n" +
            "\"alg\": \"RS256\",\n" +
            "\"kty\": \"RSA\",\n" +
            "\"use\": \"sig\",\n" +
            "\"x5c\": [\n" +
            "\"MIIDBTCCAe2gAwIBAgIJUIXnuOk2w3LCMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFWpvc2hjYW5oZWxwLmF1dGgwLmNvbTAeFw0xNzExMTUwNDIwMjlaFw0zMTA3MjUwNDIwMjlaMCAxHjAcBgNVBAMTFWpvc2hjYW5oZWxwLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOMTiEog2DK5+VCz6vbpYHa4YangyJYez1VEFPwIIKtifUfqcoV3E41Vzi+drUzGbWec8GnvAGwOzCzlMWkZBGeeKozc+Fd8RsqTXPZZDj9PKR5Kwluz8E9lzFpen9uM4i+A/B+VG4sTSDvNMWhgKARuhk1IkV9fMiuRn45RzGEZbeTelSmcxx7JVgBnpRszvI9mIlvuBsPuDKefs9XqpmlkyO+mRLbvvG6F16bf7Xwxa1bKm+XR0nSUYqiN6JdmHQzZ0Ef6oo68B7ibcFIHEZxQUjaWayip6UV+8YibnqCGBo5nRFiNHPCthnPX4+xZW7DPZDpMAt6vzMa+gx51n2MCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIiP9VWDN9iACG+5yBvhVLuIjSaIwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCbwLBKbuuDgVJiIpo0bbgqjcp3iaCGoXn43G1wByq25sv6v5laJ0Vslb7imWsY6gh9WyzhAA/MFPTaaEU7fvYtQJD2WuDzMcwfwZReIXYOMI32chlO2kbW0sw7Qhcq70JV0JPxIloPk13o4xhY59+wjh78WwvIxrMBip9naIRa4giRLbiU1hbEZJDDJ2YfN9Svf+VjjDXUJiP5GACpzOfWnUc8ZKgkgvNtwSt5XGchDNibc1egB3Dmnqbb/LKEDZ6iXywGXKcvYfk4G051i75A+DooBjutD2WV0yOJwMEP6VYE3mw/tJhTM0TzdVUtI5QzVEtWdY122obipGFRY11P\"\n" +
            "],\n" +
            "\"n\": \"4xOISiDYMrn5ULPq9ulgdrhhqeDIlh7PVUQU_Aggq2J9R-pyhXcTjVXOL52tTMZtZ5zwae8AbA7MLOUxaRkEZ54qjNz4V3xGypNc9lkOP08pHkrCW7PwT2XMWl6f24ziL4D8H5UbixNIO80xaGAoBG6GTUiRX18yK5GfjlHMYRlt5N6VKZzHHslWAGelGzO8j2YiW-4Gw-4Mp5-z1eqmaWTI76ZEtu-8boXXpt_tfDFrVsqb5dHSdJRiqI3ol2YdDNnQR_qijrwHuJtwUgcRnFBSNpZrKKnpRX7xiJueoIYGjmdEWI0c8K2Gc9fj7FlbsM9kOkwC3q_Mxr6DHnWfYw\",\n" +
            "\"e\": \"AQAB\",\n" +
            "\"kid\": \"NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA\",\n" +
            "\"x5t\": \"NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA\"\n" +
            "}]}";
    private static final String SAMPLE_JWKS_EC = "{" +
            "\"keys\":[{\n" +
            "\"kty\" : \"EC\",\n" +
            "\"crv\" : \"P-256\",\n" +
            "\"kid\" : \"NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA\",\n" +
            "\"x\"   : \"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74\",\n" +
            "\"y\"   : \"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI\",\n" +
            "\"d\"   : \"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk\"\n" +
            "}]}";
    private static final String INVALID_JSON = "{[}";
    private static final String INVALID_JWKS = "{\"keys\":[{" +
            "\"kid\" : \"cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df\",\n" +
            "\"n\"   : \"pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w\",\n" +
            "\"e\"   : \"AQAB\"" +
            "}]}";

    private static final String EMPTY_JWKS = "{\"keys\":[]}";

    @Test
    public void shouldCreateFromDomainThatStartsLikeAScheme() {
        JwkProvider jwkProvider = new JwkProvider("http2.auth0.com");
        URL url = jwkProvider.getURL();
        assertThat(url, is(notNullValue()));
        assertThat(url.toString(), is("https://http2.auth0.com/.well-known/jwks.json"));
    }

    @Test
    public void shouldCreateFromDomainWithNoScheme() {
        JwkProvider jwkProvider = new JwkProvider("samples.auth0.com");
        URL url = jwkProvider.getURL();
        assertThat(url, is(notNullValue()));
        assertThat(url.toString(), is("https://samples.auth0.com/.well-known/jwks.json"));
    }

    @Test
    public void shouldCreateFromHttpDomain() {
        JwkProvider jwkProvider = new JwkProvider("http://samples.auth0.com");
        URL url = jwkProvider.getURL();
        assertThat(url, is(notNullValue()));
        assertThat(url.toString(), is("http://samples.auth0.com/.well-known/jwks.json"));
    }

    @Test
    public void shouldCreateFromHttpsDomain() {
        JwkProvider jwkProvider = new JwkProvider("https://samples.auth0.com");
        URL url = jwkProvider.getURL();
        assertThat(url, is(notNullValue()));
        assertThat(url.toString(), is("https://samples.auth0.com/.well-known/jwks.json"));
    }

    @Test
    public void shouldFailToParseJwks() throws Exception {
        exception.expect(KeyProviderException.class);
        exception.expectMessage("Could not obtain a JWK with key id NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(JsonParseException.class));

        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(INVALID_JSON));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        PublicKey key = jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
        assertThat(key, is(notNullValue()));
        assertThat(key, IsInstanceOf.<PublicKey>instanceOf(RSAPublicKey.class));

        verify(connection).getInputStream();
        verify(connection).disconnect();
    }

    @Test
    public void shouldFailWhenJwkDoesNotContainKeyType() throws Exception {
        exception.expect(KeyProviderException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(JsonParseException.class));
        exception.expectMessage("Could not obtain a JWK with key id null");

        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(INVALID_JWKS));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        jwkProvider.getPublicKey(null);
    }

    @Test
    public void shouldFailWhenJwkIsNotRS256() throws Exception {
        exception.expect(KeyProviderException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(InvalidKeyException.class));
        exception.expectMessage("Could not obtain a JWK with key id NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");

        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(SAMPLE_JWKS_EC));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
    }

    @Test
    public void shouldFailWhenJwksIsEmpty() throws Exception {
        exception.expect(KeyProviderException.class);
        exception.expectMessage("Could not obtain a JWK with key id NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");

        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(EMPTY_JWKS));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
    }

    @Test
    public void shouldFetchJwks() throws Exception {
        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(SAMPLE_JWKS_RS));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        PublicKey key = jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
        assertThat(key, is(notNullValue()));
        assertThat(key, IsInstanceOf.<PublicKey>instanceOf(RSAPublicKey.class));

        //Calling a second time should not open a second connection
        PublicKey key2 = jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
        assertThat(key2, is(notNullValue()));
        assertThat(key2, IsInstanceOf.<PublicKey>instanceOf(RSAPublicKey.class));

        verify(connection, times(1)).getInputStream();
        verify(connection, times(1)).disconnect();
    }

    @Test
    public void shouldFetchJwksWhenKeyIdIsNotGivenAndSetContainsOneElement() throws Exception {
        final HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getInputStream()).thenReturn(new StringInputStream(SAMPLE_JWKS_RS));
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        PublicKey key = jwkProvider.getPublicKey(null);
        assertThat(key, is(notNullValue()));
        assertThat(key, IsInstanceOf.<PublicKey>instanceOf(RSAPublicKey.class));

        verify(connection).getInputStream();
        verify(connection).disconnect();
    }

    @Test
    public void shouldCloseConnectionWhenFetchFails() throws Exception {
        final HttpURLConnection connection = mock(HttpURLConnection.class);
        doThrow(IOException.class).when(connection).getInputStream();
        URLStreamHandler urlStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return connection;
            }
        };

        URL url = new URL("https", "samples.auth0.com", 80, "/.well-known/jwks.json", urlStreamHandler);
        JwkProvider jwkProvider = new JwkProvider(url);
        assertThat(jwkProvider.getURL().toString(), is("https://samples.auth0.com:80/.well-known/jwks.json"));

        PublicKey key = null;
        Exception expectedException = null;
        try {
            key = jwkProvider.getPublicKey("NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA");
        } catch (KeyProviderException e) {
            expectedException = e;
        }
        assertThat(key, is(nullValue()));
        assertThat(expectedException, is(notNullValue()));
        assertThat(expectedException.getMessage(), is("Could not obtain a JWK with key id NTIwOEI1RTBEQzlERDMwRDY0OTFCNjVDOEMxRDAxNkE1MDBFNzk5NA"));
        assertThat(expectedException.getCause(), IsInstanceOf.<Throwable>instanceOf(IOException.class));
        verify(connection).getInputStream();
        verify(connection).disconnect();
    }
}