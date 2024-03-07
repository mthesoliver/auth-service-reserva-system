package br.com.reserva.authservicereservasystem.services;


import br.com.reserva.authservicereservasystem.dto.*;
//import br.com.reserva.authservicereservasystem.enums.UserRole;
//import br.com.reserva.authservicereservasystem.exception.UserRegisterException;
import br.com.reserva.authservicereservasystem.model.Roles;
import br.com.reserva.authservicereservasystem.model.User;
import br.com.reserva.authservicereservasystem.repository.RolesRepository;
//import br.com.reserva.authservicereservasystem.repository.ServiceRepository;
import br.com.reserva.authservicereservasystem.repository.UserRepository;
//import jakarta.validation.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

//import java.util.List;
//import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RolesRepository rolesRepository;

//    @Autowired
//    private ServiceRepository serviceRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

//    public List<UserDTO> listAllUsers() {
//        return userRepository.findAll().stream().map(UserDTO::new)
//                .collect(Collectors.toList());
//    }

//    public UserByIdDTO getUserByIdOrName(String idOrName){
//        Optional<UserByIdDTO> optionalUser;
//        try {
//            Long id = Long.parseLong(idOrName);
//            optionalUser = userRepository.findById(id).map(UserByIdDTO::new);
//        }catch (NumberFormatException exception){
//            optionalUser = userRepository.findByName(idOrName).map(UserByIdDTO::new);
//        }
//        return optionalUser.orElseThrow(() -> new ValidationException("Usuário não encontrado"));
//    }

//    public List<UserByRoleDTO> getUsersByRole(UserRole role){
//        return userRepository.findByRole(role).stream().map(UserByRoleDTO::new).collect(Collectors.toList());
//    }


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

//    public void updateUserById(UserUpdateDTO dto){
//        User user = userRepository.getReferenceById(dto.id());
//        user.userUpdateData(dto);
//    }
//
//    public User deleteUserByIdOrName(String id){
//        Optional<User> optionalUser;
//        try {
//            Long parseId = Long.parseLong(id);
//            optionalUser = userRepository.findById(parseId);
//
//            if(optionalUser.isPresent()){
//                optionalUser.get().setServices();
//                userRepository.delete(optionalUser.get());
//            }
//        }catch (NumberFormatException exception){
//            throw exception;
//        }
//
//        return optionalUser.orElseThrow(() -> new ValidationException("Usuário não encontrado"));
//    }

}
