package com.hgn.iam.authn.security;

import com.hgn.iam.authn.entity.Identity;
import com.hgn.iam.authn.entity.enums.AccountStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

/**
 * UserPrincipal backed by the new Identity entity.
 * Roles come from AuthZ assignments (passed in at construction time).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserPrincipal implements UserDetails, OAuth2User {

    private Identity identity;
    private String passwordHash;
    private List<String> roles;
    private Map<String, Object> attributes;

    public static UserPrincipal create(Identity identity, String passwordHash, List<String> roles) {
        return new UserPrincipal(identity, passwordHash, roles != null ? roles : List.of(), null);
    }

    public static UserPrincipal create(Identity identity, String passwordHash, List<String> roles,
                                       Map<String, Object> attributes) {
        return new UserPrincipal(identity, passwordHash, roles != null ? roles : List.of(), attributes);
    }

    public UUID getId() {
        return identity.getId();
    }

    public String getEmail() {
        return identity.getPrimaryEmail();
    }

    @Override
    public String getName() {
        return identity.getPrimaryEmail();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (roles != null) {
            for (String role : roles) {
                String r = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                authorities.add(new SimpleGrantedAuthority(r));
            }
        }
        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return identity.getPrimaryEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return identity.getAccountStatus() != AccountStatus.DEACTIVATED;
    }

    @Override
    public boolean isAccountNonLocked() {
        return identity.getAccountStatus() != AccountStatus.LOCKED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return Boolean.TRUE.equals(identity.getEmailVerified())
                && identity.getAccountStatus() == AccountStatus.ACTIVE;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
