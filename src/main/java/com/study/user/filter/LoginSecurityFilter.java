package com.study.user.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.user.dto.vo.ResultVo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class LoginSecurityFilter {

    @Autowired
    private MyAuthenticationEntryPoint myAuthenticationEntryPoint;
    @Autowired
    private UserDetailsService userDetailsService;
    SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/user/info").permitAll() // 放行/user/info接口
                .requestMatchers("/customLogin").permitAll() // 放行customLogin接口
                // 任何请求都需要认证
                .anyRequest().authenticated()
                .and()
                // 登录接口放行，默认是/login
//                .formLogin().permitAll()
//                .and()
                // form表单登录
                .formLogin(form -> form
                        .loginPage("/login").loginProcessingUrl("/login")
                        .permitAll()
                )
                // 登出接口
                .logout()
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutSuccessUrl("/login")
                .logoutSuccessHandler(new LogoutAuthenticationFailureHandler())
                .and()
                // 禁用csrf
                .csrf().disable()
                // 未登录自定义，实现未登录返回json，非登录页面
//                .exceptionHandling()
//                .authenticationEntryPoint(myAuthenticationEntryPoint);
//                .and()
                // 防止用户多次登录
                .sessionManagement(session -> session
                        .maximumSessions(1)
                );;

        // 自定义Filter,重写UsernamePasswordAuthenticationFilter，实现application/json格式登录
//        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterAt(myConcurrentSessionFilter(), ConcurrentSessionFilter.class);

        return http.build();
    }

    @Bean
    public MyAuthenticationFilter myAuthenticationFilter() {
        MyAuthenticationFilter myAuthenticationFilter = new MyAuthenticationFilter(sessionRegistry);
        // 自定义AuthenticationManager
        myAuthenticationFilter.setAuthenticationManager(authenticationManager());
        // 登录成功处理handler,自定义返回格式及内容
        myAuthenticationFilter.setAuthenticationSuccessHandler(new MyAuthenticationSuccessHandler(sessionRegistry));
        // 登录失败处理handler,自定义返回格式及内容
        myAuthenticationFilter.setAuthenticationFailureHandler(new MyAuthenticationFailureHandler());
        // 配置Session存储方式
        myAuthenticationFilter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        ConcurrentSessionControlAuthenticationStrategy sessionStrategy=new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
        sessionStrategy.setMaximumSessions(1);
        myAuthenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
        return myAuthenticationFilter;
    }

    /**
     * 自定义AuthenticationManager
     */
    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 内存创建查询用户
//        provider.setUserDetailsService(users());
        // 数据库查询用户
        provider.setUserDetailsService(userDetailsService);
        return new ProviderManager(provider);
    }

    class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        private SessionRegistry sessionRegistry;
        public MyAuthenticationSuccessHandler(SessionRegistry sessionRegistry){
            this.sessionRegistry = sessionRegistry;
        }
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            //获取当前登录成功的用户对象
//            User user = (User) authentication.getPrincipal();
            ResultVo<User> respBean = new ResultVo();
            respBean.setCode("200");
            respBean.setMessage("登录成功");
//            respBean.setData(user);
            out.write(new ObjectMapper().writeValueAsString(respBean));
        }
    }

    class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            //获取当前登录成功的用户对象
            ResultVo<User> respBean = new ResultVo();
            respBean.setCode("403");
            respBean.setMessage("登录失败");
            out.write(new ObjectMapper().writeValueAsString(respBean));
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
        return new InMemoryUserDetailsManager(user,noopUser);
    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){
        String idForEncode = "bcrypt";
        Map encoders = new HashMap<>();
        encoders.put(idForEncode, new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public MyConcurrentSessionFilter myConcurrentSessionFilter(){
        return new MyConcurrentSessionFilter(sessionRegistry);
    }
}
