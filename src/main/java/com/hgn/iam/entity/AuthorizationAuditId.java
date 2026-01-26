package com.hgn.iam.entity;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

public class AuthorizationAuditId implements Serializable {
    private UUID id;
    private Instant timestamp;

    public AuthorizationAuditId() {
    }

    public AuthorizationAuditId(UUID id, Instant timestamp) {
        this.id = id;
        this.timestamp = timestamp;
    }

    public UUID getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationAuditId that = (AuthorizationAuditId) o;
        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        return timestamp != null ? timestamp.equals(that.timestamp) : that.timestamp == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (timestamp != null ? timestamp.hashCode() : 0);
        return result;
    }
}
