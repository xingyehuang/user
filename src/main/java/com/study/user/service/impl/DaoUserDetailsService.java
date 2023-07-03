package com.study.user.service.impl;

import ch.qos.logback.classic.spi.EventArgUtil;
import com.study.user.dto.entity.User;
import com.study.user.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.Collection;

@Service
@AllArgsConstructor
public class DaoUserDetailsService implements UserDetailsService {

    UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.lambdaQuery().eq(User::getUsername, username).one();
        if (ObjectUtils.isEmpty(user)) {
            throw new BadCredentialsException("用户不存在");
        }
        UserDetail userDetail = new UserDetail(user.getUsername(),user.getPassword());
        return userDetail;
    }

    public static void main(String[] args) {
//        UserDetail userDetail = new UserDetail("test","1234");
//        UserDetail userDetail2 = new UserDetail("test","1234");
//        System.out.println(userDetail2.equals(userDetail));

    }
     class UserDetail implements UserDetails {

        private String username;
        private String password;

        public UserDetail(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return null;
        }

        @Override
        public String getPassword() {
            return this.password;
        }

        @Override
        public String getUsername() {
            return this.username;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public int hashCode() {
            return username.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof UserDetail && this.username.equals(((UserDetail) obj).username);
        }
    }
}
