package ru.kemova.secureproject.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import ru.kemova.secureproject.dto.LoginRequest;
import ru.kemova.secureproject.dto.RegistrationRequest;
import ru.kemova.secureproject.services.AuthService;

import java.security.Principal;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    public final AuthService authService;

    @GetMapping("me")
    Principal me(Principal principal) {
        return principal;
    }

    @PostMapping("register")
    @ResponseStatus(HttpStatus.CREATED)
    void register(@RequestParam RegistrationRequest request) {
        authService.register(request);
    }

    @PostMapping("login")
    Object login(@RequestBody LoginRequest loginRequest,
                 HttpServletRequest request,
                 HttpServletResponse response) {
        return authService.login(loginRequest, request,response)
                .getPrincipal();
    }
}
