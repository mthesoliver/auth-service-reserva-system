package br.com.reserva.authservicereservasystem.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;


@RestController
@RequestMapping(value = "", method = RequestMethod.GET)
public class HomeController {
//    @GetMapping
//    public ModelAndView method() {
//        String projectUrl = "http://127.0.0.1:4200/home";
//        return new ModelAndView("redirect:" + projectUrl);
//    }
    @GetMapping
    public ResponseEntity<String> getHome(){
        return ResponseEntity.ok("Reserva.com");
    }

}
