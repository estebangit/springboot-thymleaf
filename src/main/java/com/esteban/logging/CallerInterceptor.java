package com.esteban.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CallerInterceptor extends HandlerInterceptorAdapter {

    private static Logger log = LoggerFactory.getLogger(CallerInterceptor.class);

    @Override
    public void postHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler,
            ModelAndView modelAndView) throws Exception {

        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) request.getUserPrincipal();
        String username;
        if (token == null) {
            username = "anonymous";
        } else {
            LdapUserDetails userDetails = (LdapUserDetails) token.getPrincipal();
            username = userDetails.getUsername();
        }

        log.info("[postHandle] {} - {} - {} - {} - {}",
                request.getMethod(),
                request.getRequestURI(),
                request.getRemoteUser(),
                username,
                request.getContextPath()
        );
    }

}
