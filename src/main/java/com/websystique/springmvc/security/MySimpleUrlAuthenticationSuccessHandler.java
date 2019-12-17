package com.websystique.springmvc.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;

public class MySimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException {

        Set<String> authoritySet = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
        if (authoritySet.contains("ROLE_ADMIN")) {
            response.sendRedirect("/admin/list");
        } else if (authoritySet.contains("ROLE_USER")) {
            response.sendRedirect("/user");
        } else {
            throw new IllegalStateException("!!!!!!!------>>>>the user mast be USE or ADMIN !!!!!!!!!");
        }
    }

}
