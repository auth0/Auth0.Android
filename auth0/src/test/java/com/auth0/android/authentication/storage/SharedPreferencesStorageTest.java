package com.auth0.android.authentication.storage;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import edu.emory.mathcs.backport.java.util.Collections;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyFloat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anySet;
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
        when(sharedPreferencesEditor.remove(anyString())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putString(anyString(), anyString())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putBoolean(anyString(), anyBoolean())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putLong(anyString(), anyLong())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putFloat(anyString(), anyFloat())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putInt(anyString(), anyInt())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putStringSet(anyString(), anySet())).thenReturn(sharedPreferencesEditor);
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


    //Store

    @Test
    public void shouldThrowOnStoreUnsupportedType() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The class type is not supported. Supported types are: String, Boolean, Long, Float and Integer.");
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", Collections.emptyMap(), Map.class);
    }

    @Test
    public void shouldRemovePreferencesKeyOnNullValue() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", null, String.class);
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreStringValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", "value", String.class);
        verify(sharedPreferencesEditor).putString("name", "value");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreBooleanValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", true, Boolean.class);
        verify(sharedPreferencesEditor).putBoolean("name", true);
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreLongValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", 123L, Long.class);
        verify(sharedPreferencesEditor).putLong("name", 123L);
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreFloatValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", 123F, Float.class);
        verify(sharedPreferencesEditor).putFloat("name", 123F);
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreIntegerValueOnPreferences() throws Exception {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", 123, Integer.class);
        verify(sharedPreferencesEditor).putInt("name", 123);
        verify(sharedPreferencesEditor).apply();
    }


    //Retrieve

    @Test
    public void shouldRetrieveNullValueIfMissingKeyFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(false);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Boolean value = storage.retrieve("name", Boolean.class);
        Assert.assertThat(value, is(nullValue()));
    }

    @Test
    public void shouldRetrieveStringValueFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", String.class);
        verify(sharedPreferences).getString("name", null);
    }

    @Test
    public void shouldRetrieveBooleanValueFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", Boolean.class);
        verify(sharedPreferences).getBoolean("name", false);
    }

    @Test
    public void shouldRetrieveLongValueFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", Long.class);
        verify(sharedPreferences).getLong("name", 0);
    }

    @Test
    public void shouldRetrieveFloatValueFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", Float.class);
        verify(sharedPreferences).getFloat("name", 0);
    }

    @Test
    public void shouldRetrieveIntegerValueFromPreferences() throws Exception {
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", Integer.class);
        verify(sharedPreferences).getInt("name", 0);
    }

    @Test
    public void shouldThrowOnRetrieveUnsupportedType() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The class type is not supported. Supported types are: String, Boolean, Long, Float and Integer.");
        when(sharedPreferences.contains("name")).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.retrieve("name", Map.class);
    }
}