package br.com.reserva.authservicereservasystem.model;

//import br.com.reserva.authservicereservasystem.dto.UserDTO;
//import br.com.reserva.authservicereservasystem.dto.UserUpdateDTO;
//import com.fasterxml.jackson.annotation.JsonIgnore;
import br.com.reserva.authservicereservasystem.dto.UserRegistrationDTO;
import br.com.reserva.authservicereservasystem.enums.UserRole;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

//import java.util.ArrayList;
//import java.util.List;
import java.util.Collection;
import java.util.Set;

@NoArgsConstructor
@Getter
@Entity
@Builder
@AllArgsConstructor
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Setter
    private String name;
    private String email;
    @Setter
    private String phone;
    @Enumerated(EnumType.STRING)
    @Column(name = "funcao")
    @Setter
    private UserRole role;

    @ManyToMany(fetch = FetchType.EAGER)
    @Setter
    @JoinTable(name="user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name="roles_id"))
    private Set<Roles> roles;

    private boolean expired = false;
    private boolean locked = false;
    private  boolean credentialsExpired = false;
    private boolean disable = false;

    @Setter
    private String password;

//    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
//    private List<Services> services = new ArrayList<>();
//
//    @JsonIgnore
//    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
//    private List<Reservation> reservations;

    public User(String name, String email, String phone, UserRole role){
        this.name = name;
        this.email = email;
        this.phone = phone;
        this.role = role;
    }

    public User(UserRegistrationDTO dto) {
        this.name = dto.nome();
        this.email = dto.email();
        this.phone = dto.telefone();
        this.role = dto.funcao();
    }

//    public User(UserDTO dto) {
//        this.name = dto.name();
//        this.phone = dto.phone();
//        this.email = dto.email();
//        this.role = UserRole.USER;
//    }

    public User(String name, String email, String phone) {
    }

//    public void userUpdateData(UserUpdateDTO dto){
//        this.name = dto.nome();
//        this.email = dto.email();
//        this.phone = dto.telefone();
//        this.role = dto.funcao();
//    }

    @Override
    public String toString() {
        return  "id= " + id +
                ", Nome = '" + name + '\'' +
                ", Email = '" + email + '\'' +
                ", Telefone = '" + phone + '\'' +
                ", Função = " + role;
    }

//    public void setServices() {
//        List<Services> services = new ArrayList<>();
//        this.services= services;
//    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !expired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return !disable;
    }
}

