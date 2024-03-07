package br.com.reserva.authservicereservasystem.federated;

import br.com.reserva.authservicereservasystem.model.GoogleUser;
import br.com.reserva.authservicereservasystem.repository.GoogleUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.function.Consumer;

@RequiredArgsConstructor
@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final GoogleUserRepository googleUserRepository;

    @Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        if (!this.googleUserRepository.findByEmail(user.getName()).isPresent()) {
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
            log.info(googleUser.toString());
            this.googleUserRepository.save(googleUser);
        } else {
            log.info("Bem Vindo! {}", user.getAttributes().get("given_name"));
        }
    }


}