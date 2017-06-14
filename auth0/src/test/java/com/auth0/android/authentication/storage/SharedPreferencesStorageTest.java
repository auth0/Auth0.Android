package com.auth0.android.authentication.storage;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
@SuppressLint("CommitPrefEdits")
public class SharedPreferencesStorageTest {

    @Mock
    private Context context;
    @Mock
    private SharedPreferences sharedPreferences;
    @Mock
    private SharedPreferences.Editor sharedPreferencesEditor;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(context.getSharedPreferences(anyString(), eq(Context.MODE_PRIVATE))).thenReturn(sharedPreferences);
        when(sharedPreferences.edit()).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putString(anyString(), anyString())).thenReturn(sharedPreferencesEditor);
    }

    @Test
    public void shouldCreateWithDefaultPreferencesFileName() throws Exception {
        new SharedPreferencesStorage(context);

        verify(context).getSharedPreferences("com.auth0.authentication.storage", Context.MODE_PRIVATE);
    }

    @Test
    public void shouldCreateWithCustomPreferencesFileName() throws Exception {
        new SharedPreferencesStorage(context, "my-preferences-file");

        verify(context).getSharedPreferences("my-preferences-file", Context.MODE_PRIVATE);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void shouldThrowOnCreateIfCustomPreferencesFileNameIsNull() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The SharedPreferences name is invalid");
        new SharedPreferencesStorage(context, null);
    }

    @Test
    public void shouldStoreValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", "value");
        verify(sharedPreferencesEditor).putString("name", "value");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldRetrieveValueFromPreferencesDefaultingToNull() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name");
        verify(sharedPreferences).getString("name", null);
    }
}