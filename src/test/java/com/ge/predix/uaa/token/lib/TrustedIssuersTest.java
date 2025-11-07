package com.ge.predix.uaa.token.lib;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

public class TrustedIssuersTest {

    @Test
    public void testDefaultConstructor() {
        // Test default constructor
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        assertNotNull(trustedIssuers);
        assertNull(trustedIssuers.getTrustedIssuerIds());
    }

    @Test
    public void testParameterizedConstructor() {
        // Test parameterized constructor
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2", "issuer3");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertNotNull(trustedIssuers);
        assertNotNull(trustedIssuers.getTrustedIssuerIds());
        assertEquals(trustedIssuers.getTrustedIssuerIds().size(), 3);
        assertEquals(trustedIssuers.getTrustedIssuerIds(), issuerIds);
    }

    @Test
    public void testParameterizedConstructorWithNull() {
        // Test parameterized constructor with null
        TrustedIssuers trustedIssuers = new TrustedIssuers(null);

        assertNotNull(trustedIssuers);
        assertNull(trustedIssuers.getTrustedIssuerIds());
    }

    @Test
    public void testGetTrustedIssuerIds() {
        // Test getter
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertEquals(trustedIssuers.getTrustedIssuerIds(), issuerIds);
    }

    @Test
    public void testSetTrustedIssuerIds() {
        // Test setter
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        assertNull(trustedIssuers.getTrustedIssuerIds());

        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        trustedIssuers.setTrustedIssuerIds(issuerIds);

        assertEquals(trustedIssuers.getTrustedIssuerIds(), issuerIds);
    }

    @Test
    public void testSetTrustedIssuerIdsToNull() {
        // Test setter with null
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);
        assertNotNull(trustedIssuers.getTrustedIssuerIds());

        trustedIssuers.setTrustedIssuerIds(null);
        assertNull(trustedIssuers.getTrustedIssuerIds());
    }

    @Test
    public void testEquals_SameObject() {
        // Test equals with same object (this == obj)
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertTrue(trustedIssuers.equals(trustedIssuers));
    }

    @Test
    public void testEquals_NullObject() {
        // Test equals with null object (obj == null)
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertFalse(trustedIssuers.equals(null));
    }

    @Test
    public void testEquals_DifferentClass() {
        // Test equals with different class (!(obj instanceof TrustedIssuers))
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertFalse(trustedIssuers.equals("Not a TrustedIssuers object"));
        assertFalse(trustedIssuers.equals(issuerIds));
    }

    @Test
    public void testEquals_EqualObjects() {
        // Test equals with equal objects
        List<String> issuerIds1 = Arrays.asList("issuer1", "issuer2");
        List<String> issuerIds2 = Arrays.asList("issuer1", "issuer2");

        TrustedIssuers trustedIssuers1 = new TrustedIssuers(issuerIds1);
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(issuerIds2);

        assertTrue(trustedIssuers1.equals(trustedIssuers2));
        assertTrue(trustedIssuers2.equals(trustedIssuers1));
    }

    @Test
    public void testEquals_DifferentIssuerIds() {
        // Test equals with different issuer IDs (!this.trustedIssuerIds.equals(other.trustedIssuerIds))
        List<String> issuerIds1 = Arrays.asList("issuer1", "issuer2");
        List<String> issuerIds2 = Arrays.asList("issuer3", "issuer4");

        TrustedIssuers trustedIssuers1 = new TrustedIssuers(issuerIds1);
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(issuerIds2);

        assertFalse(trustedIssuers1.equals(trustedIssuers2));
        assertFalse(trustedIssuers2.equals(trustedIssuers1));
    }

    @Test
    public void testEquals_BothNull() {
        // Test equals when both issuer IDs are null (this.trustedIssuerIds == null && other.trustedIssuerIds == null)
        TrustedIssuers trustedIssuers1 = new TrustedIssuers();
        TrustedIssuers trustedIssuers2 = new TrustedIssuers();

        assertTrue(trustedIssuers1.equals(trustedIssuers2));
        assertTrue(trustedIssuers2.equals(trustedIssuers1));
    }

    @Test
    public void testEquals_OneNullOneNotNull() {
        // Test equals when one is null and other is not (this.trustedIssuerIds == null && other.trustedIssuerIds != null)
        TrustedIssuers trustedIssuers1 = new TrustedIssuers();
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(Arrays.asList("issuer1"));

        assertFalse(trustedIssuers1.equals(trustedIssuers2));
        assertFalse(trustedIssuers2.equals(trustedIssuers1));
    }

    @Test
    public void testHashCode_WithNullIssuerIds() {
        // Test hashCode when issuer IDs are null
        TrustedIssuers trustedIssuers = new TrustedIssuers();

        int hashCode = trustedIssuers.hashCode();
        assertEquals(hashCode, 31); // prime * 1 + 0
    }

    @Test
    public void testHashCode_WithIssuerIds() {
        // Test hashCode when issuer IDs are not null
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        int hashCode = trustedIssuers.hashCode();
        int expectedHashCode = 31 + issuerIds.hashCode();
        assertEquals(hashCode, expectedHashCode);
    }

    @Test
    public void testHashCode_EqualObjects() {
        // Test that equal objects have equal hash codes
        List<String> issuerIds1 = Arrays.asList("issuer1", "issuer2");
        List<String> issuerIds2 = Arrays.asList("issuer1", "issuer2");

        TrustedIssuers trustedIssuers1 = new TrustedIssuers(issuerIds1);
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(issuerIds2);

        assertEquals(trustedIssuers1.hashCode(), trustedIssuers2.hashCode());
    }

    @Test
    public void testHashCode_DifferentObjects() {
        // Test that different objects may have different hash codes
        List<String> issuerIds1 = Arrays.asList("issuer1", "issuer2");
        List<String> issuerIds2 = Arrays.asList("issuer3", "issuer4");

        TrustedIssuers trustedIssuers1 = new TrustedIssuers(issuerIds1);
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(issuerIds2);

        assertNotEquals(trustedIssuers1.hashCode(), trustedIssuers2.hashCode());
    }

    @Test
    public void testToString_WithIssuerIds() {
        // Test toString with issuer IDs
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        String result = trustedIssuers.toString();
        assertEquals(result, "TrustedIssuers [trustedIssuerIds=[issuer1, issuer2]]");
        assertTrue(result.contains("TrustedIssuers"));
        assertTrue(result.contains("trustedIssuerIds"));
        assertTrue(result.contains("issuer1"));
        assertTrue(result.contains("issuer2"));
    }

    @Test
    public void testToString_WithNullIssuerIds() {
        // Test toString with null issuer IDs
        TrustedIssuers trustedIssuers = new TrustedIssuers();

        String result = trustedIssuers.toString();
        assertEquals(result, "TrustedIssuers [trustedIssuerIds=null]");
        assertTrue(result.contains("TrustedIssuers"));
        assertTrue(result.contains("null"));
    }

    @Test
    public void testToString_WithEmptyList() {
        // Test toString with empty list
        TrustedIssuers trustedIssuers = new TrustedIssuers(new ArrayList<>());

        String result = trustedIssuers.toString();
        assertEquals(result, "TrustedIssuers [trustedIssuerIds=[]]");
        assertTrue(result.contains("TrustedIssuers"));
        assertTrue(result.contains("[]"));
    }

    @Test
    public void testCompleteWorkflow() {
        // Test a complete workflow using all methods
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        assertNull(trustedIssuers.getTrustedIssuerIds());

        List<String> issuerIds = Arrays.asList("issuer1", "issuer2", "issuer3");
        trustedIssuers.setTrustedIssuerIds(issuerIds);
        assertEquals(trustedIssuers.getTrustedIssuerIds(), issuerIds);

        TrustedIssuers anotherIssuers = new TrustedIssuers(issuerIds);
        assertTrue(trustedIssuers.equals(anotherIssuers));
        assertEquals(trustedIssuers.hashCode(), anotherIssuers.hashCode());

        String stringRepresentation = trustedIssuers.toString();
        assertTrue(stringRepresentation.contains("issuer1"));
        assertTrue(stringRepresentation.contains("issuer2"));
        assertTrue(stringRepresentation.contains("issuer3"));
    }

    @Test
    public void testMutableList() {
        // Test with mutable list to ensure behavior is consistent
        List<String> issuerIds = new ArrayList<>(Arrays.asList("issuer1", "issuer2"));
        TrustedIssuers trustedIssuers = new TrustedIssuers(issuerIds);

        assertEquals(trustedIssuers.getTrustedIssuerIds().size(), 2);

        // Modify the original list
        issuerIds.add("issuer3");

        // The object's list should be affected (same reference)
        assertEquals(trustedIssuers.getTrustedIssuerIds().size(), 3);
    }

    @Test
    public void testEqualsAndHashCodeContract() {
        // Test equals and hashCode contract
        List<String> issuerIds = Arrays.asList("issuer1", "issuer2");
        TrustedIssuers trustedIssuers1 = new TrustedIssuers(issuerIds);
        TrustedIssuers trustedIssuers2 = new TrustedIssuers(issuerIds);
        TrustedIssuers trustedIssuers3 = new TrustedIssuers(issuerIds);

        // Reflexive: x.equals(x) should be true
        assertTrue(trustedIssuers1.equals(trustedIssuers1));

        // Symmetric: x.equals(y) should be same as y.equals(x)
        assertTrue(trustedIssuers1.equals(trustedIssuers2));
        assertTrue(trustedIssuers2.equals(trustedIssuers1));

        // Transitive: if x.equals(y) and y.equals(z), then x.equals(z)
        assertTrue(trustedIssuers1.equals(trustedIssuers2));
        assertTrue(trustedIssuers2.equals(trustedIssuers3));
        assertTrue(trustedIssuers1.equals(trustedIssuers3));

        // Consistent hash codes
        assertEquals(trustedIssuers1.hashCode(), trustedIssuers2.hashCode());
        assertEquals(trustedIssuers2.hashCode(), trustedIssuers3.hashCode());
    }
}

