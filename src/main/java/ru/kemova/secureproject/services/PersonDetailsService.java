//package ru.kemova.secureproject.services;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import ru.kemova.secureproject.models.Person;
//import ru.kemova.secureproject.repositories.PeopleRepository;
//import ru.kemova.secureproject.security.PersonDetails;
//
//@Service
//@RequiredArgsConstructor
//public class PersonDetailsService implements UserDetailsService {
//
//    private final PeopleRepository peopleRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        Person person = peopleRepository.findByUsername(username).orElseThrow(() ->
//                new UsernameNotFoundException("User not found"));
//        return new PersonDetails(person);
//    }
//}
