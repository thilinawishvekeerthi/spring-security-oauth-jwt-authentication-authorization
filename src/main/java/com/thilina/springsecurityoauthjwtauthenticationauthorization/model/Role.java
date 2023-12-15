package com.thilina.springsecurityoauthjwtauthenticationauthorization.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;


@Getter
@Setter
@Builder
@AllArgsConstructor
@Entity
@Table(uniqueConstraints = {@UniqueConstraint(name = "unique_role", columnNames = {"name"})})
public class Role {

    public Role(){}

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @NotNull
    @Column(nullable = false)
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<AppUser> appUsers= new HashSet<>();
}
