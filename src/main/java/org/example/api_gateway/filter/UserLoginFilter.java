package org.example.api_gateway.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class UserLoginFilter extends OncePerRequestFilter {

    private static final String LOGIN_HEADER = "X-User-Login";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        var authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        if (!(authentication instanceof JwtAuthenticationToken jwt)
                || !jwt.isAuthenticated()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String login = jwt.getToken()
                .getClaimAsString("preferred_username");

        if (login == null || login.isBlank()) {
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "В токене отсутствует логин"
            );
            return;
        }

        HttpServletRequest wrappedRequest =
                new HttpServletRequestWrapper(request) {

                    @Override
                    public String getHeader(String name) {
                        if (LOGIN_HEADER.equalsIgnoreCase(name)) {
                            return login;
                        }
                        return super.getHeader(name);
                    }

                    @Override
                    public Enumeration<String> getHeaders(String name) {
                        if (LOGIN_HEADER.equalsIgnoreCase(name)) {
                            return Collections.enumeration(List.of(login));
                        }
                        return super.getHeaders(name);
                    }

                    @Override
                    public Enumeration<String> getHeaderNames() {
                        List<String> names = new ArrayList<>();

                        Enumeration<String> originalNames =
                                super.getHeaderNames();

                        while (originalNames.hasMoreElements()) {
                            String name = originalNames.nextElement();

                            if (!LOGIN_HEADER.equalsIgnoreCase(name)) {
                                names.add(name);
                            }
                        }

                        names.add(LOGIN_HEADER);
                        return Collections.enumeration(names);
                    }
                };

        filterChain.doFilter(wrappedRequest, response);
    }
}