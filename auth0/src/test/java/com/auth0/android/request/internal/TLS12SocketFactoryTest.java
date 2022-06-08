package com.auth0.android.request.internal;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Ignore
public class TLS12SocketFactoryTest {

    private static final String TLS_1_2 = "TLSv1.2";
    private static final String MOCK_HOST = "www.example.com";
    private static final int MOCK_PORT = 8080;
    private static final int MOCK_LOCAL_PORT = 8081;
    private static final boolean MOCK_AUTO_CLOSE = true;

    @Mock SSLSocket socket;
    @Mock SSLSocketFactory delegate;
    TLS12SocketFactory factory;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        factory = new TLS12SocketFactory(delegate);
    }

    @Test
    public void shouldGetDefaultCipherSuites() {
        String[] suites = new String[]{"Test"};
        when(delegate.getDefaultCipherSuites()).thenReturn(suites);

        String[] result = factory.getDefaultCipherSuites();

        verify(delegate).getDefaultCipherSuites();
        assertTrue(Arrays.equals(result, suites));
    }

    @Test
    public void shouldGetSupportedCipherSuites() {
        String[] suites = new String[]{"Test"};
        when(delegate.getSupportedCipherSuites()).thenReturn(suites);

        String[] result = factory.getSupportedCipherSuites();

        verify(delegate).getSupportedCipherSuites();
        assertTrue(Arrays.equals(result, suites));
    }

    @Test
    public void shouldCreateSocket_socket_host_port_autoClose() throws IOException {
        when(delegate.createSocket(any(Socket.class), anyString(), anyInt(), anyBoolean()))
                .thenReturn(socket);

        Socket result = factory.createSocket(socket, MOCK_HOST, MOCK_PORT, MOCK_AUTO_CLOSE);

        assertEquals(result, socket);
        verify(delegate).createSocket(eq(socket), eq(MOCK_HOST), eq(MOCK_PORT), eq(MOCK_AUTO_CLOSE));
        verifyPatched(result);
    }

    @Test
    public void shouldCreateSocket_host_port() throws IOException {
        when(delegate.createSocket(anyString(), anyInt()))
                .thenReturn(socket);

        Socket result = factory.createSocket(MOCK_HOST, MOCK_PORT);

        assertEquals(result, socket);
        verify(delegate).createSocket(eq(MOCK_HOST), eq(MOCK_PORT));
        verifyPatched(result);
    }

    @Test
    public void shouldCreateSocket_host_port_localHost_localPort() throws IOException {
        InetAddress localHost = mock(InetAddress.class);
        when(delegate.createSocket(anyString(), anyInt(), any(InetAddress.class), anyInt()))
                .thenReturn(socket);

        Socket result = factory.createSocket(MOCK_HOST, MOCK_PORT, localHost, MOCK_LOCAL_PORT);

        assertEquals(result, socket);
        verify(delegate).createSocket(eq(MOCK_HOST), eq(MOCK_PORT), eq(localHost), eq(MOCK_LOCAL_PORT));
        verifyPatched(result);
    }

    @Test
    public void shouldCreateSocket_hostAddress_port() throws IOException {
        InetAddress host = mock(InetAddress.class);
        when(delegate.createSocket(any(InetAddress.class), anyInt()))
                .thenReturn(socket);

        Socket result = factory.createSocket(host, MOCK_PORT);

        assertEquals(result, socket);
        verify(delegate).createSocket(eq(host), eq(MOCK_PORT));
        verifyPatched(result);
    }

    @Test
    public void shouldCreateSocket_address_port_localAddress_localPort() throws IOException {
        InetAddress address = mock(InetAddress.class);
        InetAddress localAddress = mock(InetAddress.class);
        when(delegate.createSocket(any(InetAddress.class), anyInt(), any(InetAddress.class), anyInt()))
                .thenReturn(socket);

        Socket result = factory.createSocket(address, MOCK_PORT, localAddress, MOCK_LOCAL_PORT);

        assertEquals(result, socket);
        verify(delegate).createSocket(eq(address), eq(MOCK_PORT), eq(localAddress), eq(MOCK_LOCAL_PORT));
        verifyPatched(result);
    }


    private static void verifyPatched(Socket socket) {
        ArgumentCaptor<String[]> captor = ArgumentCaptor.forClass(String[].class);
        assertTrue(socket instanceof SSLSocket);
        verify((SSLSocket)socket).setEnabledProtocols(captor.capture());
        String[] protocols = captor.getValue();
        boolean patched = false;
        for (String string : protocols) {
            if (TLS_1_2.equals(string)) {
                patched = true;
                break;
            }
        }
        assertTrue(patched);
    }
}
