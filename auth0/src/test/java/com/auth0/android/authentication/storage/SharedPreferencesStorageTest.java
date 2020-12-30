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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyFloat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anySetOf;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
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
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        when(context.getSharedPreferences(anyString(), eq(Context.MODE_PRIVATE))).thenReturn(sharedPreferences);
        when(sharedPreferences.edit()).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.remove(anyString())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putString(anyString(), anyString())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putBoolean(anyString(), anyBoolean())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putLong(anyString(), anyLong())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putFloat(anyString(), anyFloat())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putInt(anyString(), anyInt())).thenReturn(sharedPreferencesEditor);
        when(sharedPreferencesEditor.putStringSet(anyString(), anySetOf(String.class))).thenReturn(sharedPreferencesEditor);
    }

    @Test
    public void shouldCreateWithDefaultPreferencesFileName() {
        new SharedPreferencesStorage(context);
        verify(context).getSharedPreferences("com.auth0.authentication.storage", Context.MODE_PRIVATE);
    }

    @Test
    public void shouldCreateWithCustomPreferencesFileName() {
        new SharedPreferencesStorage(context, "my-preferences-file");
        verify(context).getSharedPreferences("my-preferences-file", Context.MODE_PRIVATE);
    }

    @Test
    public void shouldThrowOnCreateIfCustomPreferencesFileNameIsEmpty() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The SharedPreferences name is invalid");
        //noinspection ConstantConditions
        new SharedPreferencesStorage(context, "");
    }


    //Store

    @Test
    public void shouldStoreStringValueOnPreferences() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", "value");
        verify(sharedPreferencesEditor).putString("name", "value");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreLongValueOnPreferences() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", 123L);
        verify(sharedPreferencesEditor).putLong("name", 123L);
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreIntegerValueOnPreferences() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", 123);
        verify(sharedPreferencesEditor).putInt("name", 123);
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldStoreBooleanValueOnPreferences() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.store("name", true);
        verify(sharedPreferencesEditor).putBoolean("name", true);
        verify(sharedPreferencesEditor).apply();
    }


    //Retrieve

    @Test
    public void shouldRetrieveNullStringValueIfMissingKeyFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(false);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        String value = storage.retrieveString("name");
        assertThat(value, is(nullValue()));
    }

    @Test
    public void shouldRetrieveNullLongValueIfMissingKeyFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(false);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Long value = storage.retrieveLong("name");
        assertThat(value, is(nullValue()));
    }

    @Test
    public void shouldRetrieveNullIntegerValueIfMissingKeyFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(false);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Integer value = storage.retrieveInteger("name");
        assertThat(value, is(nullValue()));
    }

    @Test
    public void shouldRetrieveNullBooleanValueIfMissingKeyFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(false);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Boolean value = storage.retrieveBoolean("name");
        assertThat(value, is(nullValue()));
    }

    @Test
    public void shouldRetrieveStringValueFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(true);
        when(sharedPreferences.getString("name", null)).thenReturn("value");
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        String value = storage.retrieveString("name");
        assertThat(value, is("value"));
    }

    @Test
    public void shouldRetrieveLongValueFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(true);
        when(sharedPreferences.getLong("name", 0)).thenReturn(1234567890L);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Long value = storage.retrieveLong("name");
        assertThat(value, is(1234567890L));
    }

    @Test
    public void shouldRetrieveIntegerValueFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(true);
        when(sharedPreferences.getInt("name", 0)).thenReturn(123);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Integer value = storage.retrieveInteger("name");
        assertThat(value, is(123));
    }

    @Test
    public void shouldRetrieveBooleanValueFromPreferences() {
        when(sharedPreferences.contains("name")).thenReturn(true);
        when(sharedPreferences.getBoolean("name", false)).thenReturn(true);
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Boolean value = storage.retrieveBoolean("name");
        assertThat(value, is(true));
    }


    //Remove

    @Test
    public void shouldRemovePreferencesKeyOnNullStringValue() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        String value = null;
        //noinspection ConstantConditions
        storage.store("name", value);
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldRemovePreferencesKeyOnNullLongValue() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Long value = null;
        storage.store("name", value);
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldRemovePreferencesKeyOnNullIntegerValue() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Integer value = null;
        storage.store("name", value);
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldRemovePreferencesKeyOnNullBooleanValue() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        Boolean value = null;
        storage.store("name", value);
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

    @Test
    public void shouldRemovePreferencesKey() {
        SharedPreferencesStorage storage = new SharedPreferencesStorage(context);
        storage.remove("name");
        verify(sharedPreferencesEditor).remove("name");
        verify(sharedPreferencesEditor).apply();
    }

}