package com.auth0.android.util

import java.util.Collections
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.Callable
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/**
 * A custom implementation of ExecutorService that executes the tasks synchronously instead of asynchronously.
 */

internal class CustomExecutorService : AbstractExecutorService() {
    private var isShutdown = false

    override fun shutdown() {
        isShutdown = true
    }

    override fun shutdownNow(): List<Runnable> {
        isShutdown = true
        return Collections.emptyList()
    }

    override fun isShutdown(): Boolean = isShutdown

    override fun isTerminated(): Boolean = isShutdown

    override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = true

    override fun execute(command: Runnable?) {
        if (isShutdown) throw IllegalStateException("Executor has been shut down")
        command?.run()
    }

    override fun <T : Any?> submit(task: Callable<T>?): Future<T> {
        if(isShutdown) throw IllegalStateException("Executor has been shut down")
        // execute the task here itself and return the response
        return object : Future<T> {
            override fun cancel(mayInterruptIfRunning: Boolean): Boolean = false
            override fun isCancelled(): Boolean = false
            override fun isDone(): Boolean = true
            override fun get(): T = task?.call()!!
            override fun get(timeout: Long, unit: TimeUnit): T = task?.call()!!
        }
    }
}