package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class UserInfoTest {

    private Map<String, Object> values;
    private UserInfo userInfo;

    @Before
    public void setUp() throws Exception {
        values = Mockito.mock(Map.class);
        userInfo = new UserInfo(values);
    }

    @Test
    public void getValues() throws Exception {
        assertThat(userInfo.getValues(), is(values));
    }
}