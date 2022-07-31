package com.gmarquezp.springbootclientes.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gmarquezp.springbootclientes.models.entities.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
 * Clase que contendra la logica de autenticacion, solo se ejecutara en /api/login
 * */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private AuthenticationManager authenticationManager;

    // Generando una llave secreta
    public static SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        // Definimos la nueva url del Login => /api/login
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {


        // Recibe los parametros como form data
        String username = this.obtainUsername(request);
        String password = this.obtainPassword(request);

        // Si son null, validaremos si recibimos como string raw
        if (username == null || password == null) {
            try {
                // Convertimos el string raw a objeto
                Usuario user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);

                username = user.getUsername();
                password = user.getPassword();

            } catch (IOException e) {
                logger.error("Fuck, la autenticacion fallo al recibir los parametros como string raw");
                throw new RuntimeException(e);
            }

        }


        System.out.println("=".repeat(100));
        System.out.println("=".repeat(100));
        System.out.println("=".repeat(100));
        logger.info("Username: " + username);
        logger.info("Password: " + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);


        return this.authenticationManager.authenticate(authToken); // Se devuelve la autenticacion
    }


    /*
     * Metodo que se ejecuta cuando attemptAuthentication es efectivo
     * */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {


        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(authResult.getAuthorities()));

        String token = Jwts.builder()
                .setSubject(authResult.getName()) // authResult.getName() // devuelve el username del usuario que se loggeo
                .setClaims(claims) // Setea los claims
                .signWith(secretKey) // setea el secreto de encriptacion
                .setIssuedAt(new Date()) // Fecha de creacion del token
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // Fecha de expiracion del token
                .compact();

        // Agrega en el header  el token
        response.addHeader("Authorization", "Bearer " + token);

        // Body que se retornara, transformado en json
        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        // body.put("authorities", authResult.getAuthorities());
        body.put("message", "Has iniciado sesion correctamente");

        // ObjectMapper().writeValueAsString(body) // Convierte el objeto en JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    /*
     * Metodo que se ejecuta cuando attemptAuthentication NO es efectivo
     * */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {

        Map<String, Object> body = new HashMap<>();
        body.put("message", "Error de autenticacion usuario o contraseña");
        body.put("error", failed.getMessage());

        // ObjectMapper().writeValueAsString(body) // Convierte el objeto en JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401); // 401 = Unauthorized
        response.setContentType("application/json");


    }
}
