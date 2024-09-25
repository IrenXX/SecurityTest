package ru.kemova.secureproject.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import ru.kemova.secureproject.security.PersonDetails;
import ru.kemova.secureproject.services.AdminService;

@Controller
@RequiredArgsConstructor
public class HelloController {
    private final AdminService adminService;

    @GetMapping("/hello")
    public String sayHello() {
        return "hello";
    }

    @GetMapping("/showUserInfo")
    public String shawUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        PersonDetails personDetails = (PersonDetails) authentication.getPrincipal();
        System.out.println(personDetails.person());
        return "hello";
    }

    @GetMapping("/admin")
    public String adminPage(){
        adminService.doAdmin();
        return "admin";
    }

}
