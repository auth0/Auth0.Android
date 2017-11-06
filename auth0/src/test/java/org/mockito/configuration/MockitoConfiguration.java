package org.mockito.configuration;

public class MockitoConfiguration extends DefaultMockitoConfiguration {

    // Disabling class cache for mockito as suggested in exception message
    // https://stackoverflow.com/questions/33008255/classcastexception-exception-when-running-robolectric-test-with-power-mock-on-mu

    @Override
    public boolean enableClassCache() {
        return false;
    }
}