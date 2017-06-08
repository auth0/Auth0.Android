package com.auth0.android.provider;

import android.content.Intent;

/**
 * Created by lbalmaceda on 6/12/17.
 */

public class AuthenticationActivityMock extends AuthenticationActivity {

    private CustomTabsController customTabsController;
    private Intent deliveredIntent;

    @Override
    protected CustomTabsController createCustomTabsController() {
        return customTabsController;
    }

    @Override
    protected void deliverSuccessfulAuthenticationResult(Intent result) {
        this.deliveredIntent = result;
        super.deliverSuccessfulAuthenticationResult(result);
    }

    public void setCustomTabsController(CustomTabsController customTabsController) {
        this.customTabsController = customTabsController;
    }

    public Intent getDeliveredIntent() {
        return deliveredIntent;
    }
}
