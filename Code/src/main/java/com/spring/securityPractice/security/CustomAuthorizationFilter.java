package com.spring.securityPractice.security;

import com.spring.securityPractice.SpringApplicationContext;
import com.spring.securityPractice.constants.AppConstants;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(AppConstants.HEADER_STRING);
        if (header == null || !header.startsWith(AppConstants.TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
        } else {
            Authentication authentication = getAuthenticationToken(header);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(request, response);
        }
    }

    private Authentication getAuthenticationToken(String header) {
        if (header != null) {
            String token = header.replace(AppConstants.TOKEN_PREFIX, "");
            String user = JWTUtils.hasTokenExpired(token) ? null : JWTUtils.extractUser(token);

            if (user != null) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                UserService userService = (UserService) SpringApplicationContext.getBean("userServiceImpl");
                String userRole = userService.getUser(user).getRole();
                authorities.add(new SimpleGrantedAuthority("ROLE_" + userRole));

                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }
        }
        return null;
    }
}
