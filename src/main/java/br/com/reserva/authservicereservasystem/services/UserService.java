package br.com.reserva.authservicereservasystem.services;


import br.com.reserva.authservicereservasystem.dto.MessageDTO;
import br.com.reserva.authservicereservasystem.dto.UserRegistrationDTO;
import br.com.reserva.authservicereservasystem.model.Roles;
import br.com.reserva.authservicereservasystem.model.User;
import br.com.reserva.authservicereservasystem.repository.RolesRepository;
import br.com.reserva.authservicereservasystem.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RolesRepository rolesRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    public MessageDTO userRegistration(UserRegistrationDTO dto){
        boolean alreadyExists = userRepository.existsByPhoneOrEmail(dto.telefone(), dto.email());

        if(alreadyExists){
            throw new RuntimeException("Dados de usuário já existentes");
        }else{
            User user = new User(dto);
            user.setPassword(passwordEncoder.encode(dto.password()));
            Set<Roles> roles = rolesRepository.findByRole(dto.funcao()).stream().collect(Collectors.toSet());
            user.setRoles(roles);
            userRepository.save(user);
            return new MessageDTO("Usuário " + user.getEmail() + " salvo com sucesso");
        }
    }
}