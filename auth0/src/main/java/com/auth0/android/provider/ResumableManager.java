package com.auth0.android.provider;

/**
 * Internal class, used to generify the handling of different Web Auth flows.
 * See {@link WebAuthProvider}
 */
abstract class ResumableManager {

    /**
     * Invoked when a result of a Web Auth flow is available
     *
     * @param result a result created from an {@link android.content.Intent}.
     * @return whether the result was expected and valid or not. Error or cancel scenarios are also considered valid.
     * @see AuthorizeResult
     */
    abstract boolean resume(AuthorizeResult result);
}
