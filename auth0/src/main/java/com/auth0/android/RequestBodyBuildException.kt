package com.auth0.android

/**
 * Exception that wraps errors when creating a body for a request
 */
public class RequestBodyBuildException(message: String, cause: Throwable?) :
    Auth0Exception(message, cause)