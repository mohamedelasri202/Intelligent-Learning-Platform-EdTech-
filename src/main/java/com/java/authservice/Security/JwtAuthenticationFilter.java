package com.java.authservice.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hibernate.query.NativeQuery;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import jakarta.servlet.ServletException;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;


@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter (JwtService jwtService , UserDetailsService userDetailsService){
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected  void doFilterInternal (
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
            ) throws ServletException , IOException {


                final String  authHeader = request.getHeader("Authorization");
                final String jwt ;
                final String userEmail ;

        if(authHeader.isEmpty() || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }
            jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);

        if(userEmail != null && SecurityContextHolder.getConext().getAuthantication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt , userDetails)){
                UsernamePasswordAuthenticationToken authToken =  new UsernamePasswordAuthenticationToken(userDetails,null ,userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthantication(authToken);
            }
        }
        filterChain.doFilter(request ,response);
    }






}
