package br.com.reserva.authservicereservasystem.repository;


import br.com.reserva.authservicereservasystem.enums.UserRole;
import br.com.reserva.authservicereservasystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByPhoneOrEmail(String telefone, String email);

    List<User> findByRole(UserRole role);

    Optional<User> findByEmail(String email);
}

