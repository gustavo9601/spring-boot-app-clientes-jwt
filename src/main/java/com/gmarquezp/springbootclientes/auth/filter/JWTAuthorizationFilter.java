package com.gmarquezp.springbootclientes.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gmarquezp.springbootclientes.auth.SimpleGrantedAuthorityMixin;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/*
 * Metodo que escaneara las rutas, que esten configuradas con proteccion para identificar si vieneno ono el token
 * */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        // Capturamos el header
        String header = request.getHeader("Authorization");

        // Si no existe el header, seguimos con el filtro
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return; // Salimos del filtro
        }


        // Generando una llave secreta
        SecretKey secretKey = JWTAuthenticationFilter.secretKey;

        // Obtenemos el token y se valida
        boolean isValid = false;
        Claims claimsToken = null;
        try {
            claimsToken = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(header.replace("Bearer ", ""))// removemos el Bearer para que quede solo el token
                    .getBody();

            isValid = true;

        } catch (JwtException | IllegalArgumentException exception) {
            logger.error("Token invalido omee!!!");
            logger.error(exception.getMessage());
            isValid = false;
        }

        // Si el token es valido, seguimos con el filtro
        UsernamePasswordAuthenticationToken authentication = null;
        if (isValid) {
            String userName = claimsToken.getSubject();
            Object roles = claimsToken.get("authorities");

            // Creamos una autenticacion con el usuario y roles
            Collection<? extends GrantedAuthority> authorities = Arrays.asList(
                    new ObjectMapper()
                            .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class) // Mix entre la clase propia de Spring Security y la personalizada
                            .readValue(roles.toString(), SimpleGrantedAuthority[].class));
            authentication = new UsernamePasswordAuthenticationToken(userName, null, authorities);
        }

        // Autenticamos al usuario dentro del contexto, es decir dentro del request ya estaria autenticado para continuar
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);

    }


}
