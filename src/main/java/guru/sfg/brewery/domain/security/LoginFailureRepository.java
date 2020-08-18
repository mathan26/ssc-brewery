package guru.sfg.brewery.domain.security;

import guru.sfg.brewery.domain.security.LoginFailure;
import org.springframework.data.jpa.repository.JpaRepository;


public interface LoginFailureRepository extends JpaRepository<LoginFailure, Integer> {
}