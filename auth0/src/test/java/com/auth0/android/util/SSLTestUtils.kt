package com.auth0.android.util

import com.auth0.android.request.DefaultClient
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.InetAddress

/**
 * Utility object for executing tests that use the networking client over HTTPS on localhost.
 */
internal object SSLTestUtils {
    private val localhostCertificate: HeldCertificate
    private val serverCertificates: HandshakeCertificates
    val clientCertificates: HandshakeCertificates
    val testClient: DefaultClient

    init {
        val localhost = InetAddress.getByName("localhost").canonicalHostName

        localhostCertificate = HeldCertificate.Builder()
            .addSubjectAlternativeName(localhost)
            .build()

        clientCertificates = HandshakeCertificates.Builder()
            .addTrustedCertificate(localhostCertificate.certificate)
            .build()

        serverCertificates = HandshakeCertificates.Builder()
            .heldCertificate(localhostCertificate)
            .build()

        testClient = DefaultClient(
            defaultHeaders = mapOf(),
            readTimeout = 10,
            connectTimeout = 10,
            enableLogging = false,
            sslSocketFactory = clientCertificates.sslSocketFactory(),
            trustManager = clientCertificates.trustManager
        )
    }

    fun createMockWebServer(): MockWebServer {
        val mockServer = MockWebServer()
        mockServer.useHttps(serverCertificates.sslSocketFactory(), false)
        return mockServer
    }
}