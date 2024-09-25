//package ru.kemova.secureproject.security;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//import ru.kemova.secureproject.services.PersonDetailsService;
//
//import java.util.Collections;
//
//@Component
//@RequiredArgsConstructor
//public class AuthenticationProviderImpl implements org.springframework.security.authentication.AuthenticationProvider {
//
//    private final PersonDetailsService personDetailsService;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String username = authentication.getName();
//        UserDetails personDetails = personDetailsService.loadUserByUsername(username);
//        String password =authentication.getCredentials().toString();
//        if (!password.equals(personDetails.getPassword())) {
//            throw new BadCredentialsException("Password Incorrect");
//        }
//
//        return new UsernamePasswordAuthenticationToken(personDetails,
//                password, Collections.EMPTY_LIST);
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return true;
//    }
//}
