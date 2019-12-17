package com.websystique.springmvc.security;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.websystique.springmvc.model.User;
import com.websystique.springmvc.model.UserProfile;
import com.websystique.springmvc.service.UserService;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private UserService userService;

    public UserDetailsServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String ssoId)
            throws UsernameNotFoundException {
        User user = userService.findBySSO(ssoId);
        if (user == null) {
            throw new UsernameNotFoundException("Username not found");
        }
        return new org.springframework.security.core.userdetails.User(
                user.getSsoId(),
                user.getPassword(),
                true,
                true,
                true,
                true,
                user.getUserProfiles()
                        .stream()
                        .map(p -> new SimpleGrantedAuthority("ROLE_" + p.getType()))
                        .collect(Collectors.toList())
        );
    }
}
