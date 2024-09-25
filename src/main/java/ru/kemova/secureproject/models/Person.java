package ru.kemova.secureproject.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@Entity
@Table(name = "person")
@NoArgsConstructor
@ToString
public class Person {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private int id;

    @NotEmpty
    @Size(min = 2, max = 30)
    private String username;

    @NotEmpty
    @Email
    private String email;
    private String role = "ROLE_USER";
    private String password;

    @Enumerated(EnumType.STRING)
    private AuthType authType;
}
