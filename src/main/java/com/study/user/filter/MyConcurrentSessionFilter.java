package com.study.user.filter;

import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.ConcurrentSessionFilter;

public class MyConcurrentSessionFilter extends ConcurrentSessionFilter {

    public MyConcurrentSessionFilter(SessionRegistry sessionRegistry) {
        super(sessionRegistry);
    }
}
