package ru.kemova.secureproject.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import ru.kemova.secureproject.dto.LoginRequest;
import ru.kemova.secureproject.dto.RegistrationRequest;
import ru.kemova.secureproject.models.AuthType;
import ru.kemova.secureproject.models.Person;
import ru.kemova.secureproject.repositories.PeopleRepository;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final PeopleRepository peopleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public void register(RegistrationRequest request) {
        if (peopleRepository.existsByEmailAndAuthType(request.email(), AuthType.MANUAL)) {
            throw new IllegalArgumentException("Email already registered");
        }

        var user = new Person();
        user.setAuthType(AuthType.MANUAL);
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        peopleRepository.save(user);
    }

    public Authentication login(LoginRequest loginRequest, HttpServletRequest request,
                                HttpServletResponse response) {
        var passwordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginRequest.email(),
                        loginRequest.password());

        var auth = authenticationManager.authenticate(passwordAuthenticationToken);
        var securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(auth);
        securityContextRepository.saveContext(securityContext, request, response); // сохраняем новую сессию

        log.info("Authenticated and created session for {}", auth.getName());
        return auth;
    }
}

