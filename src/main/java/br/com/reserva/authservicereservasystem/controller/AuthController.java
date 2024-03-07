package br.com.reserva.authservicereservasystem.controller;


import br.com.reserva.authservicereservasystem.dto.MessageDTO;
import br.com.reserva.authservicereservasystem.dto.UserRegistrationDTO;
import br.com.reserva.authservicereservasystem.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<MessageDTO> userRegister(@RequestBody UserRegistrationDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.userRegistration(dto));

    }
}
