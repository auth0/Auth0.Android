package com.auth0.android.result;

import androidx.annotation.Nullable;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

@SuppressWarnings("WeakerAccess")
public class CredentialsMock extends Credentials {

    public static final long CURRENT_TIME_MS = calculateCurrentTime();

    public CredentialsMock(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Long expiresIn) {
        super(idToken, accessToken, type, refreshToken, expiresIn);
    }

    public CredentialsMock(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Date expiresAt, @Nullable String scope) {
        super(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }

    @Override
    long getCurrentTimeInMillis() {
        return CURRENT_TIME_MS;
    }

    private static long calculateCurrentTime() {
        Calendar cal = Calendar.getInstance();
        cal.setTimeZone(TimeZone.getTimeZone("UTC"));
        return cal.getTimeInMillis();
    }
}
