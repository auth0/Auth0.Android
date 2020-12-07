package com.auth0.android.request.kt

import android.os.Handler
import android.os.Looper
import androidx.core.os.HandlerCompat
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

internal object ThreadUtils {
    private const val MAX_CONCURRENT_THREADS = 4

    val mainThreadHandler: Handler by lazy {
        HandlerCompat.createAsync(Looper.getMainLooper())
    }
    val executorService: ExecutorService by lazy {
        Executors.newFixedThreadPool(MAX_CONCURRENT_THREADS)
    }

}