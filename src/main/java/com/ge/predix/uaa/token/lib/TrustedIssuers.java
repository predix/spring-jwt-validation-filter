/*
 * Copyright (c) 2015 General Electric Company. All rights reserved.
 *
 * The copyright to the computer software herein is the property of
 * General Electric Company. The software may be used and/or copied only
 * with the written permission of General Electric Company or in accordance
 * with the terms and conditions stipulated in the agreement/contract
 * under which the software has been supplied.
 */
package com.ge.predix.uaa.token.lib;

import java.util.List;

public class TrustedIssuers {
    private List<String> trustedIssuerIds;

    public TrustedIssuers(final List<String> trustedIssuerIds) {
        this.trustedIssuerIds = trustedIssuerIds;
    }

    public TrustedIssuers() {
        // default constructor
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((this.trustedIssuerIds == null) ? 0 : this.trustedIssuerIds.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof TrustedIssuers)) {
            return false;
        }
        TrustedIssuers other = (TrustedIssuers) obj;
        if (this.trustedIssuerIds == null) {
            if (other.trustedIssuerIds != null) {
                return false;
            }
        } else if (!this.trustedIssuerIds.equals(other.trustedIssuerIds)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "TrustedIssuers [trustedIssuerIds=" + this.trustedIssuerIds + "]";
    }

    public List<String> getTrustedIssuerIds() {
        return this.trustedIssuerIds;
    }

    public void setTrustedIssuerIds(final List<String> trustedIssuerIds) {
        this.trustedIssuerIds = trustedIssuerIds;
    }
}