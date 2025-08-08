package com.auth0.android.request

import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPUtil
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

        //Storing the DPoP nonce if present in the response
        DPoP.storeNonce(response)

        //Handling DPoP Nonce retry
        if (DPoP.isNonceRequiredError(response) && currentRetryCount < DPoPUtil.MAX_RETRY_COUNT) {
            val accessToken =
                request.headers[AUTHORIZATION_HEADER]?.substringAfter(DPOP_LIMITER)?.trim()
            val dpopProof = DPoPUtil.generateProof(
                httpUrl = request.url.toString(),
                httpMethod = request.method,
                accessToken = accessToken,
                nonce = DPoP.auth0Nonce
            )
            if (dpopProof != null) {
                response.close()
                val newRequest = request.newBuilder()
                    .header(DPoPUtil.DPOP_HEADER, dpopProof)
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