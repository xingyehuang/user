package com.study.user.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.user.dto.vo.ResultVo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * 登录失败，自定义返回格式
 */
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        //获取当前登录成功的用户对象
        ResultVo<User> respBean = new ResultVo();
        respBean.setCode("401");
        if (authException instanceof InsufficientAuthenticationException) {
            respBean.setMessage("请先登录");
        } else if (authException instanceof BadCredentialsException) {
            respBean.setMessage("用户名或密码错误");
        } else {
            respBean.setMessage("用户认证失败，请检查后重试");
        }
        out.write(new ObjectMapper().writeValueAsString(respBean));
    }
}
