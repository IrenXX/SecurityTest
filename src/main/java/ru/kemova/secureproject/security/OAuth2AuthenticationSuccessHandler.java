package ru.kemova.secureproject.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import ru.kemova.secureproject.models.Person;
import ru.kemova.secureproject.repositories.PeopleRepository;

import java.io.IOException;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // Данные поля подходят только github api
    record EmailDetails(String email, Boolean primary, Boolean verified) {
    }

    private final PeopleRepository peopleRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestClient restClient = RestClient.builder()
            .baseUrl("https://api.github.com/user/emails") // другой url если другой провайдер соответственно
            .build(); // лучше получать это значение с ClientRegistration

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication auth) throws IOException {
        if (auth instanceof OAuth2AuthenticationToken auth2AuthenticationToken) {
            var principal = auth2AuthenticationToken.getPrincipal();
            var username = principal.getName();
            var email = fetchUserEmailFromGitHubApi(auth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                    username);

            if (!peopleRepository.existsByEmail(email)) {
                var user = new Person();
                user.setEmail(email);
                user.setUsername(username);
                peopleRepository.save(user);
            }
        }

        super.clearAuthenticationAttributes(request);
        super.getRedirectStrategy().sendRedirect(request, response, "/api/v1/user/me");
    }

    private String fetchUserEmailFromGitHubApi(String clientRegistrationId, String principalName) {
        var authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, principalName);
        var accessToken = authorizedClient.getAccessToken().getTokenValue();

        var userEmailsResponse = restClient.get()
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .body(EmailDetails[].class);

        if (userEmailsResponse == null) {
            return "null";
        }

        var fetchedEmailDetails = Arrays.stream(userEmailsResponse)
                .filter(emailDetails -> emailDetails.verified() && emailDetails.primary())
                .findFirst()
                .orElseGet(() -> null);

        return fetchedEmailDetails != null ? fetchedEmailDetails.email() : "null";
    }
}
