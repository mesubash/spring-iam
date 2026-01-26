package com.hgn.iam.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

public final class IpRangeMatcher {

    private IpRangeMatcher() {
    }

    public static boolean isInRange(String ipAddress, String cidr) {
        if (ipAddress == null || cidr == null || cidr.isBlank()) {
            return false;
        }

        String[] parts = cidr.split("/");
        String network = parts[0].trim();
        int prefixLength = parts.length > 1 ? Integer.parseInt(parts[1].trim()) : -1;

        try {
            InetAddress ip = InetAddress.getByName(ipAddress);
            InetAddress net = InetAddress.getByName(network);

            byte[] ipBytes = ip.getAddress();
            byte[] netBytes = net.getAddress();

            if (ipBytes.length != netBytes.length) {
                return false;
            }

            int maxPrefix = ipBytes.length * 8;
            int prefix = prefixLength >= 0 ? prefixLength : maxPrefix;

            if (prefix < 0 || prefix > maxPrefix) {
                return false;
            }

            BigInteger ipVal = new BigInteger(1, ipBytes);
            BigInteger netVal = new BigInteger(1, netBytes);

            BigInteger mask = prefix == 0
                    ? BigInteger.ZERO
                    : BigInteger.ONE.shiftLeft(maxPrefix).subtract(BigInteger.ONE)
                    .shiftRight(maxPrefix - prefix).shiftLeft(maxPrefix - prefix);

            return ipVal.and(mask).equals(netVal.and(mask));
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }
}
