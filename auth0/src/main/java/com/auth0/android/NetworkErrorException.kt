package com.auth0.android

/**
 * Exception that represents a failure caused when attempting to execute a network request
 */
public class NetworkErrorException(cause: Throwable) :
    Auth0Exception("Failed to execute the network request", cause)