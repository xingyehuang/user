package com.study.user.controller;

import com.study.user.dto.LoginForm;
import com.study.user.dto.entity.User;
import com.study.user.dto.vo.ResultVo;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {

//    @Autowired
    AuthenticationManager authenticationManager;

    @GetMapping("/login")
    String login() {
        System.out.println("login");
        return "login";
    }

    @GetMapping("/logout")
    String logout() {
        System.out.println("logout");
        return "logout";
    }

    @GetMapping("/logoutSuccess")
    String logoutSuccess() {
        System.out.println("logoutSuccess");
        return "logoutSuccess";
    }


    /**
     * 自定义json Login方式2，controller方式
     * */
//    @PostMapping("/customLogin")
//    @ResponseBody
//    public ResultVo customLogin(@RequestBody LoginForm form, HttpSession session) {
//        UsernamePasswordAuthenticationToken unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(form.getUsername(), form.getPassword());
//        Authentication authenticate = authenticationManager.authenticate(unauthenticated);
//        SecurityContextHolder.getContext().setAuthentication(authenticate);
//        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
//        UserDetails principal = (UserDetails) authenticate.getPrincipal();
//        return ResultVo.success(principal);
//    }

}
