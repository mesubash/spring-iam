package com.hgn.iam.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpRangeMatcherTest {

    @Test
    void matchesIpv4Cidr() {
        assertTrue(IpRangeMatcher.isInRange("192.168.1.5", "192.168.1.0/24"));
        assertFalse(IpRangeMatcher.isInRange("192.168.2.5", "192.168.1.0/24"));
    }

    @Test
    void matchesSingleHost() {
        assertTrue(IpRangeMatcher.isInRange("10.0.0.1", "10.0.0.1/32"));
        assertFalse(IpRangeMatcher.isInRange("10.0.0.2", "10.0.0.1/32"));
    }

    @Test
    void handlesInvalidInput() {
        assertFalse(IpRangeMatcher.isInRange(null, "10.0.0.0/8"));
        assertFalse(IpRangeMatcher.isInRange("10.0.0.1", null));
        assertFalse(IpRangeMatcher.isInRange("invalid", "10.0.0.0/8"));
    }
}
