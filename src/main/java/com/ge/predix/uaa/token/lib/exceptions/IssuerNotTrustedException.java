package com.ge.predix.uaa.token.lib.exceptions;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

@SuppressWarnings("serial")
public class IssuerNotTrustedException extends InvalidTokenException {

    public IssuerNotTrustedException(final String msg) {
        super(msg);
   }

    public IssuerNotTrustedException(final String msg, final Throwable t) {
        super(msg, t);
    }

    public String getOAuth2ErrorCode() {
        return "issuer_not_trusted";
    }
}
