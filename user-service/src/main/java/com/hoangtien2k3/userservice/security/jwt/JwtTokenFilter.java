package com.hoangtien2k3.userservice.security.jwt;

import com.hoangtien2k3.userservice.security.userprinciple.UserDetailService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);

    private final JwtProvider jwtProvider;
    private final UserDetailService userDetailService;

    public JwtTokenFilter(JwtProvider jwtProvider, UserDetailService userDetailService) {
        this.jwtProvider = jwtProvider;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String token = extractJwtFromHeader(request);

            if (token != null && jwtProvider.validateToken(token)) {

                String username = jwtProvider.getUserNameFromToken(token);

                UserDetails userDetails = userDetailService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(auth);

                // Optional: Refresh token handling
                String refreshToken = jwtProvider.createRefreshToken(auth);

                response.setHeader("Authorization", "Bearer " + token);
                response.setHeader("Refresh-Token", refreshToken);
            }

        } catch (Exception e) {
            logger.error("JWT Authentication failed: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwtFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();  // Remove "Bearer "
        }

        return null;
    }
}
