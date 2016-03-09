package com.ge.predix.uaa.token.lib;

import java.util.List;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.util.AntPathMatcher;

public class DefaultZoneConfiguration {
    private String trustedIssuerId;
    private List<String> allowedUriPatterns;

    public String getTrustedIssuerId() {
        return this.trustedIssuerId;
    }

    @Required
    public void setTrustedIssuerId(final String trustedIssuerId) {
        this.trustedIssuerId = trustedIssuerId;
    }

    /**
     * A list of Ant-style path patterns as supported by {@linkplain AntPathMatcher}
     * 
     * @return
     */
    public List<String> getAllowedUriPatterns() {
        return this.allowedUriPatterns;
    }

    @Required
    public void setAllowedUriPatterns(final List<String> allowedUriPatterns) {
        AntPathMatcher matcher = new AntPathMatcher();

        for (String pattern : allowedUriPatterns) {
            if (!matcher.isPattern(pattern)) {
                throw new IllegalArgumentException("Invalid pattern: " + pattern);
            }
        }
        this.allowedUriPatterns = allowedUriPatterns;
    }

}
