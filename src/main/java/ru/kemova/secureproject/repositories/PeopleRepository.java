package ru.kemova.secureproject.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.kemova.secureproject.models.AuthType;
import ru.kemova.secureproject.models.Person;

import java.util.Optional;

public interface PeopleRepository extends JpaRepository<Person, Integer> {

    Optional<Person> findByUsername(String username);

    boolean existsByEmailAndAuthType(String email, AuthType authType);

    boolean existsByEmail(String email);

    Optional<Person> findByEmailAndAuthType(String email, AuthType authType);
}
