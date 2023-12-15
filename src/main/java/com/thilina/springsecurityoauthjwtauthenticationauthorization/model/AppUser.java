package com.thilina.springsecurityoauthjwtauthenticationauthorization.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;


@Getter
@Setter
@Builder
@AllArgsConstructor
@Entity
@Table(uniqueConstraints = {@UniqueConstraint(name = "unique_email", columnNames = {"email"})})
public class AppUser {

    public AppUser(){}

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String providerUserId;

    @NotNull
    @NotBlank
    @Column(nullable = false)
    private String displayName;

    @Email
    @NotNull
    @NotBlank
    @Column(nullable = false)
    private String email;

    @NotNull
    @NotBlank
    @Column(nullable = false)
    private String password;

    private String provider;

    private boolean enabled = false;

    private boolean accountNonExpired = true;

    private boolean credentialsNonExpired = true;

    private boolean accountNonLocked = true;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "app_user_roles",
            joinColumns = @JoinColumn(name = "app_user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    public void grantRole(Role role) {
        roles.add(role);
        role.getAppUsers().add(this);
    }

    public void grantRoles(Set<Role> roles) {
        roles.forEach(role -> {
            roles.add(role);
            role.getAppUsers().add(this);
        });
    }

    public void removeRoles(Set<Role> roles) {
        roles.forEach(role -> {
            roles.remove(role);
            role.getAppUsers().remove(this);
        });

    }

    public void removeRole(Role role) {
        roles.remove(role);
        role.getAppUsers().remove(this);
    }

    public Set<GrantedAuthority> getAuthorities(){
      return  this.roles
              .stream()
              .map(Role::getName)
              .map(SimpleGrantedAuthority:: new)
              .collect(Collectors.toSet());
    }
}
