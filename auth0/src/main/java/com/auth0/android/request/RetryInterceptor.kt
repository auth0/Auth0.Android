package com.auth0.android.request

import com.auth0.android.dpop.DPoPProvider
import okhttp3.Interceptor
import okhttp3.Response

/**
 * Interceptor that retries requests.
 */
internal class RetryInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val retryCountHeader = request.header(RETRY_COUNT_HEADER)
        val currentRetryCount = retryCountHeader?.toIntOrNull() ?: 0
        val response = chain.proceed(request)

        //Handling DPoP Nonce retry
        if (DPoPProvider.isNonceRequiredError(response) && currentRetryCount < DPoPProvider.MAX_RETRY_COUNT) {
            DPoPProvider.storeNonce(response)
            val accessToken =
                request.headers[AUTHORIZATION_HEADER]?.substringAfter(DPOP_LIMITER)?.trim()
            val dpopProof = DPoPProvider.generateProof(
                httpUrl = request.url.toString(),
                httpMethod = request.method,
                accessToken = accessToken,
                nonce = DPoPProvider.auth0Nonce
            )
            if (dpopProof != null) {
                response.close()
                val newRequest = request.newBuilder()
                    .header(DPoPProvider.DPOP_HEADER, dpopProof)
                    .header(RETRY_COUNT_HEADER, (currentRetryCount + 1).toString())
                    .build()
                return chain.proceed(newRequest)
            }
        }
        return response
    }

    private companion object {
        private const val RETRY_COUNT_HEADER = "X-Internal-Retry-Count"
        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val DPOP_LIMITER = "DPoP "
    }

}