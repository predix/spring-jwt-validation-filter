package com.ge.predix.uaa.token.lib;

import java.io.IOException;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.DefaultResponseErrorHandler;

public class FastTokenServicesResponseErrorHandler extends DefaultResponseErrorHandler {
    /* (non-Javadoc)
     * @see org.springframework.web.client.DefaultResponseErrorHandler#handleError(org.springframework.http.client.ClientHttpResponse)
     * We overrode this method to ignore 400 errors.
     */
    @Override
    public void handleError(final ClientHttpResponse response) throws IOException {
        if (response.getRawStatusCode() != 400) {
            super.handleError(response);
        }
    }
}
