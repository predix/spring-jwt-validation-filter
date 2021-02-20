/*******************************************************************************
 * Copyright 2021 General Electric Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

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
