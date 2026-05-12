package io.github.christyjohn.security.core.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.List;

public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // roles → ROLE_
        List<String> roles = jwt.getClaim("roles");
        if (roles != null) {
            roles.forEach(role ->
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role))
            );
        }

        // permissions → direct
        List<String> permissions = jwt.getClaim("permissions");
        if (permissions != null) {
            permissions.forEach(permission ->
                    authorities.add(new SimpleGrantedAuthority(permission))
            );
        }

        Long userId = Long.valueOf(jwt.getSubject());

        return new UsernamePasswordAuthenticationToken(
                userId,
                null,
                authorities
        );
    }
}
