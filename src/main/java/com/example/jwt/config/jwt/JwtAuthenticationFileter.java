package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// /login 요청해서 username, password 전송하면 (post) 이 필터가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFileter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
  @SneakyThrows
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    // 1. username, password 받아서
    // 1-1 출력방법1
//    BufferedReader br = request.getReader();
//    String input = null;
//    while((input = br.readLine()) != null) {
//      System.out.println(input); // username=eden&password=1111
//    }
    // 1-2 출력방법2
    ObjectMapper om = new ObjectMapper();
    User user = om.readValue(request.getInputStream(), User.class);
    System.out.println(user); // User(id=0, username=eden, password=1111, roles=null)

    // 2. 로그인 시도 -> authenticationManager로 로그인 시도를 하면 PrincipalDetailsService의 loadUserByUsername() 함수 실행됨
    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
        user.getUsername(), user.getPassword());

    // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
    Authentication authentication = authenticationManager.authenticate(authenticationToken);

    // 4. authentication 객체가 session 영역에 저장됨 -> 로그인 성공
    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    System.out.println("로그인 완료 : " + principalDetails.getUser().getUsername());

    // 5. session 리턴 이유는 권한 관리를 security가 대신 해주니까 편하려고 하는 거임
    return authentication;
  }

  // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 실행
  // JWT 토큰을 만들어서 request 요청한 사용자에게 토큰을 response 해줌
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    System.out.println("successfulAuthentication 실행됨 -> 인증 완료");

    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    // RSA방식은 아니고 Hash암호방식
    String jwtToken = JWT.create()
        .withSubject("jwt token - eden")
        .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
        .withClaim("id", principalDetails.getUser().getId())
        .withClaim("username", principalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
  }
}
