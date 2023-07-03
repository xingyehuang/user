package com.study.user.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.user.dto.vo.ResultVo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * 基于Form的账号密码登录
 *
 * @author xyh
 */
@Configuration
public class LoginSecurityFormFilter {


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/user/info").permitAll() // 放行/user/info接口
                .requestMatchers("/customLogin").permitAll() // 放行customLogin接口
                // 任何请求都需要认证
                .anyRequest().authenticated()
                .and()
                // form表单登录
                .formLogin(form -> form
                                .loginPage("/login") // 指定跳转页面
//                        .loginProcessingUrl("/login") // 指定验证登录的接口地址
                                .permitAll()
                )
                // 登出接口
                .logout(logout -> {
                    logout.logoutUrl("/logout"); // 自定义登出接口地址
                    logout.invalidateHttpSession(true);
                    logout.clearAuthentication(true);
                    logout.logoutSuccessUrl("/logoutSuccess").permitAll(); // 登出后跳转的页面
                    // 自定义登出响应处理，当配置logoutSuccessHandler时，则logoutSuccessUrl失效
                    logout.logoutSuccessHandler(new LogoutAuthenticationFailureHandler());
                })
                // 禁用csrf
                .csrf().disable()
                // 未登录自定义，实现未登录返回json，非登录页面
//                .exceptionHandling()
//                .authenticationEntryPoint(myAuthenticationEntryPoint);
//                .and()
                // 防止用户多次登录
                .sessionManagement(session -> session
                        .maximumSessions(1)
                );

        return http.build();
    }


    /**
     * 内存创建用户的方式模拟用户
     */
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{bcrypt}$2a$10$lXBVHUgzG.gv1HBBpPudPOas4H7InrLBMe8o.GzJpOHFS9KC4uIwa")
                .roles("USER")
                .build();
        UserDetails noopUser = User.builder()
                .username("noopUser")
                .password("{noop}password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, noopUser);
    }

    /**
     * 自定义AuthenticationManager
     */
    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 内存创建查询用户
        provider.setUserDetailsService(users());
        return new ProviderManager(provider);
    }

    /**
     * 自定义密码加密算法
     */
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        String idForEncode = "bcrypt";
        Map encoders = new HashMap<>();
        encoders.put(idForEncode, new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }

}

class LogoutAuthenticationFailureHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        //获取当前登录成功的用户对象
        ResultVo<User> respBean = new ResultVo();
        respBean.setCode("401");
        respBean.setMessage("登出成功");
        out.write(new ObjectMapper().writeValueAsString(respBean));
    }
}