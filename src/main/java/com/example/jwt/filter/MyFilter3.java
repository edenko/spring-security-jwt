package com.example.jwt.filter;

import com.example.jwt.config.jwt.JwtProperties;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
      FilterChain filterChain) throws IOException, ServletException {

    // 다운캐스팅
    HttpServletRequest req = (HttpServletRequest) servletRequest;
    HttpServletResponse res = (HttpServletResponse) servletResponse;

    // 토큰 : abc
    if(req.getMethod().equals("POST")) {
      String headerAuth = req.getHeader(JwtProperties.HEADER_STRING);
      System.out.println("필터3");
      if(headerAuth.equals("abc")) {
        filterChain.doFilter(req, res);
      }else {
        res.setCharacterEncoding("UTF-8");
        res.setContentType("text/html; charset=UTF-8");
        PrintWriter out = res.getWriter();
        out.println("인증안됨");
      }
    }
  }
}
