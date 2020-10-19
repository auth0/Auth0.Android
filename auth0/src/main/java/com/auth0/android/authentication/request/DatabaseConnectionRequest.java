package com.auth0.android.authentication.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import java.util.Map;

/**
 * Request to perform a non-authentication related action
 * like creating a user or requesting a change password
 */
public class DatabaseConnectionRequest<T, U extends Auth0Exception> {

    private final ParameterizableRequest<T, U> request;

    public DatabaseConnectionRequest(@NonNull ParameterizableRequest<T, U> request) {
        this.request = request;
    }

    /**
     * Add the given parameters to the request
     *
     * @param parameters to be sent with the request
     * @return itself
     */
    @NonNull
    public DatabaseConnectionRequest<T, U> addParameters(@NonNull Map<String, Object> parameters) {
        request.addParameters(parameters);
        return this;
    }

    /**
     * Add a parameter by name to the request
     *
     * @param name  of the parameter
     * @param value of the parameter
     * @return itself
     */
    @NonNull
    public DatabaseConnectionRequest<T, U> addParameter(@NonNull String name, @NonNull Object value) {
        request.addParameter(name, value);
        return this;
    }

    /**
     * Add a header to the request, e.g. "Authorization"
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    @NonNull
    public DatabaseConnectionRequest<T, U> addHeader(@NonNull String name, @NonNull String value) {
        request.addHeader(name, value);
        return this;
    }

    /**
     * Set the Auth0 Database Connection used for this request using its name.
     *
     * @param connection name
     * @return itself
     */
    @NonNull
    public DatabaseConnectionRequest<T, U> setConnection(@NonNull String connection) {
        request.addParameter(ParameterBuilder.CONNECTION_KEY, connection);
        return this;
    }

    /**
     * Executes the request async and returns its results via callback
     *
     * @param callback called on success or failure of the request
     */
    public void start(@NonNull BaseCallback<T, U> callback) {
        request.start(callback);
    }

    /**
     * Executes the request synchronously
     *
     * @return the request result
     * @throws Auth0Exception if the request failed
     */
    @NonNull
    public T execute() throws Auth0Exception {
        return request.execute();
    }
}
