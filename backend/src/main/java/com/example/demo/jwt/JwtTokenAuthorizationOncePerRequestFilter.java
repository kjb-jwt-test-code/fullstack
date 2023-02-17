package com.example.demo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

// API 요청을 할 때마다 사용자가 인증되어있는지 확인하는 필터
@Component
public class JwtTokenAuthorizationOncePerRequestFilter extends OncePerRequestFilter {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final List<String> EXCLUDE_URL = Collections.unmodifiableList(Arrays.asList(
            "/static/**",
            "/favicon.ico",
            "/api/authenticate"));

    public static final String AUTHORIZATION_HEADER = "Authorization";
    @Autowired
    private UserDetailsService jwtInMemoryUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private TokenProvider tokenProvider;

    @Value("${jwt.http.request.header}")
    private String tokenHeader;

    @Value("${token.cookie.name}")
    private String tokenCookieName;

    // 쿠키에서 토큰을 불러오는 방식
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpServletRequest httpServletRequest = request;
        String jwt = resolveToken(httpServletRequest);

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
//        logger.debug("Authentication Request for '{}'", request.getRequestURL());
//        Cookie[] cookies = request.getCookies();
//        String username = null;
//        String jwtToken = null;
//        if (cookies != null) {
//            for (Cookie cookie : cookies) {
//                if (cookie.getName().equals(tokenCookieName)) {
//                    jwtToken = cookie.getValue();
//                    break;
//                }
//            }
//        }
//        if (jwtToken != null) {
//            try {
//                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
//            } catch (IllegalArgumentException e) {
//                logger.error("JWT_TOKEN_UNABLE_TO_GET_USERNAME", e);
//            } catch (ExpiredJwtException e) {
//                logger.warn("JWT_TOKEN_EXPIRED", e);
//            }
//        } else {
//            logger.warn("JWT_TOKEN_DOES_NOT_EXIST");
//        }
//        logger.debug("JWT_TOKEN_USERNAME_VALUE '{}'", username);
//        UserDetails userDetails = null;
//        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            userDetails = this.jwtInMemoryUserDetailsService.loadUserByUsername(username);
//            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
//                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//                        userDetails,
//                        null,
//                        userDetails.getAuthorities());
//                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext()
//                        .setAuthentication(usernamePasswordAuthenticationToken);
//            }
//        }
//        filterChain.doFilter(request, response);

    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return EXCLUDE_URL.stream()
                .anyMatch(exclude -> exclude.equalsIgnoreCase(request.getServletPath()));
    }
}