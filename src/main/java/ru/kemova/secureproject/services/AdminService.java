package ru.kemova.secureproject.services;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class AdminService {

    @PreAuthorize(value = "hasRole('ROLE_ADMIN')")
    public void doAdmin() {
        System.out.println("Only admin here");
    }
}
