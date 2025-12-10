package com.hoangtien2k3.userservice.security.userprinciple;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hoangtien2k3.userservice.model.entity.User;
import com.hoangtien2k3.userservice.model.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.With;
import lombok.experimental.Accessors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@With
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Accessors(fluent = true)
public class UserPrinciple implements UserDetails {

    private Long id;
    private String fullname;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private String gender;
    private String phone;
    private String avatar;

    private Collection<? extends GrantedAuthority> authorities;

    public static UserPrinciple build(User user) {

        // Convert roles to SimpleGrantedAuthority
        List<GrantedAuthority> grantedAuthorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return UserPrinciple.builder()
                .id(user.getId())
                .fullname(user.getFullname())
                .username(user.getUsername())
                .email(user.getEmail())
                .password(user.getPassword())
                .gender(user.getGender())
                .phone(user.getPhone())
                .avatar(user.getAvatar())
                .authorities(grantedAuthorities)
                .build();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
