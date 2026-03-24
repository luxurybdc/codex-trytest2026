package com.example.auth.config;

import com.example.auth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    public static final String JWT_COOKIE_NAME = "AUTH_TOKEN";
    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/css") || path.startsWith("/login") || path.startsWith("/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = getTokenFromCookie(request.getCookies());
        if (token == null) {
            response.sendRedirect("/login");
            return;
        }

        try {
            String username = jwtUtil.parseUsername(token);
            request.setAttribute("loginUser", username);
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            response.sendRedirect("/login?error=token");
        }
    }

    private String getTokenFromCookie(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (JWT_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
