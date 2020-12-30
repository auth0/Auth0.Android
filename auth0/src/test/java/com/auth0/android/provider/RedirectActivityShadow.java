package com.auth0.android.provider;

import android.content.Intent;

import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.shadows.ShadowActivity;

/**
 * Shadow that keeps track of the started activity and the finished state.
 */
@Implements(RedirectActivity.class)
public class RedirectActivityShadow extends ShadowActivity {

    public Intent startedIntent = null;
    public boolean isFinishing = false;

    @Implementation
    public void startActivity(Intent intent) {
        startedIntent = intent;
    }

    @Implementation
    public void finish() {
        isFinishing = true;
    }

}