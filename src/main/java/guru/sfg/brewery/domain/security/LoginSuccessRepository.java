package guru.sfg.brewery.domain.security;

import guru.sfg.brewery.domain.security.LoginSuccess;
import org.springframework.data.jpa.repository.JpaRepository;


public interface LoginSuccessRepository extends JpaRepository<LoginSuccess, Integer> {
}