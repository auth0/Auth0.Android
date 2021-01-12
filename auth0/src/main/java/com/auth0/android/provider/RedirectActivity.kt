package com.auth0.android.provider

import android.app.Activity
import android.content.Intent
import android.os.Bundle

public class RedirectActivity : Activity() {
    public override fun onCreate(savedInstanceBundle: Bundle?) {
        super.onCreate(savedInstanceBundle)
        val intent = Intent(this, AuthenticationActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        if (getIntent() != null) {
            intent.data = getIntent().data
        }
        startActivity(intent)
        finish()
    }
}