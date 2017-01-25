package com.auth0.android.result;

import org.hamcrest.collection.IsMapWithSize;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class UserInfoTest {

    @Test
    public void getValues() throws Exception {
        Map<String, Object> values = Mockito.mock(Map.class);
        UserInfo userInfo = new UserInfo(values);
        assertThat(userInfo.getValues(), is(values));
    }

    @Test
    public void getEmptyValues() throws Exception {
        UserInfo userInfo = new UserInfo(null);
        assertThat(userInfo.getValues(), IsMapWithSize.anEmptyMap());
    }
}