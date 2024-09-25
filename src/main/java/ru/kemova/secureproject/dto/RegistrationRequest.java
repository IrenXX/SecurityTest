package ru.kemova.secureproject.dto;

public record RegistrationRequest(String email, String password,
                                  String username) {
}
