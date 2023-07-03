package com.study.user.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.Map;


/**
 *
 *
 *
 * 自定义json Login方式1，重写Filter
 * 重写UsernamePasswordAuthenticationFilter.attemptAuthentication()方法，实现对json登录表单信息的拦截
 *
 * */
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private SessionRegistry sessionRegistry;
    public MyAuthenticationFilter(SessionRegistry sessionRegistry){
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        if (request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)) {
            try {
                Map<String, String> userMap = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userMap.get("username"), userMap.get("password"));
                this.setDetails(request, token);
                Authentication authenticate = this.getAuthenticationManager().authenticate(token);
                sessionRegistry.registerNewSession(request.getSession().getId(),authenticate.getPrincipal());
                return authenticate;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }
}
