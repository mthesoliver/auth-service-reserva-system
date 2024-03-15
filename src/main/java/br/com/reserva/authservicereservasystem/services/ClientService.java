package br.com.reserva.authservicereservasystem.services;

import br.com.reserva.authservicereservasystem.dto.ClientRegisterDTO;
import br.com.reserva.authservicereservasystem.dto.MessageDTO;
import br.com.reserva.authservicereservasystem.model.Client;
import br.com.reserva.authservicereservasystem.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {

    @Autowired
    private final ClientRepository clientRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    private Client clientFromDto(ClientRegisterDTO dto){
        Client client = Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requireProofKey(dto.isRequireProofKey())
                .build();
        return client;
    }

    public MessageDTO registerClient(ClientRegisterDTO dto){
        Client client = clientFromDto(dto);
        clientRepository.save(client);
        return new MessageDTO("Client " + client.getClientId() + " salvo com sucesso");
    }

    @Override
    public void save(RegisteredClient registeredClient) {
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findByClientId(id)
                .orElseThrow(() -> new RuntimeException("Client não encontrado"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("Client não encontrado"));
        return Client.toRegisteredClient(client);
    }
}
