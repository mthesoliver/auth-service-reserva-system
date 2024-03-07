package br.com.reserva.authservicereservasystem.repository;

import br.com.reserva.authservicereservasystem.enums.UserRole;
import br.com.reserva.authservicereservasystem.model.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RolesRepository extends JpaRepository<Roles, Long> {
    Optional<Roles> findByRole(UserRole rolesName);
}
