package com.ge.predix.uaa.token.lib;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.HttpServerErrorException;
import org.testng.annotations.Test;

public class FastTokenServicesResponseErrorHandlerTest {

    @Test
    public void handleError_Ignores400Error() throws IOException {
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(response.getStatusCode()).thenReturn(HttpStatusCode.valueOf(400));
        when(response.getHeaders()).thenReturn(headers);
        when(headers.getContentType()).thenReturn(MediaType.APPLICATION_JSON);

        FastTokenServicesResponseErrorHandler errorHandler = new FastTokenServicesResponseErrorHandler();
        errorHandler.handleError(response);

        verify(response, never()).close();
    }

    @Test(expectedExceptions = HttpServerErrorException.class)
    public void handleError_HandlesNon400Error() throws IOException {
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(response.getStatusCode()).thenReturn(HttpStatusCode.valueOf(500));
        when(response.getBody()).thenReturn(new ByteArrayInputStream("500 error".getBytes()));
        when(response.getHeaders()).thenReturn(headers);
        when(headers.getContentType()).thenReturn(MediaType.APPLICATION_JSON);

        FastTokenServicesResponseErrorHandler errorHandler = new FastTokenServicesResponseErrorHandler();
        errorHandler.handleError(response);

        verify(response).close();
    }

}