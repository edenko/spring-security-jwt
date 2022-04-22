package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// security filter 중에 BasicAutnenticationFileter가 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있음
// 만약, 권한이나 인증이 필요한 주소가 아니라면 이 필터는 안탐
public class JwtAuthorizationFileter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  public JwtAuthorizationFileter(
      AuthenticationManager authenticationManager,
      UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {
//    super.doFilterInternal(request, response, chain);
//    System.out.println("권한/인증이 필요합니다.");

    String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
    System.out.println("jwtHeader : " + jwtHeader);

    // header 확인
    if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
      chain.doFilter(request, response);
      return;
    }

    // jwt 토큰을 검증해서 정상적인 사용자인지 확인
    String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
    String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken)
        .getClaim("username").asString();

    if(username != null) {
      User userEntity = userRepository.findByUsername(username);
      PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

      // jwt토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만듬
      Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,
          null, principalDetails.getAuthorities());

      // security 저장 가능한 세션 공간을 찾아서, Authentication 객체를 저장
      SecurityContextHolder.getContext().setAuthentication(authentication);

      chain.doFilter(request, response);
    }
  }
}
