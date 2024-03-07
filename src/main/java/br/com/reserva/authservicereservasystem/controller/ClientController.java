package br.com.reserva.authservicereservasystem.controller;


import br.com.reserva.authservicereservasystem.dto.ClientRegisterDTO;
import br.com.reserva.authservicereservasystem.dto.MessageDTO;
import br.com.reserva.authservicereservasystem.services.ClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client")
@RequiredArgsConstructor
@Slf4j
public class ClientController {

    @Autowired
    private final ClientService clientService;

    @PostMapping("/register")
    public ResponseEntity<MessageDTO> registerClient(@RequestBody ClientRegisterDTO dto){
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.registerClient(dto));
    }

}
