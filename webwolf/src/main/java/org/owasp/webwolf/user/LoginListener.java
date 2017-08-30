package org.owasp.webwolf.user;

import lombok.AllArgsConstructor;
import org.owasp.webgoat.login.LoginEvent;
import org.owasp.webgoat.login.LogoutEvent;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@Component
@AllArgsConstructor
public class LoginListener {
    
    private final WebGoatUserToCookieRepository repository;

    @JmsListener(destination = "webgoat", containerFactory = "jmsFactory", selector = "type = 'LoginEvent'")
    public void loginEvent(LoginEvent loginEvent) {
        repository.save(new WebGoatUserCookie(loginEvent.getUser(), loginEvent.getCookie()));
    }

    @JmsListener(destination = "webgoat", containerFactory = "jmsFactory", selector = "type = 'LogoutEvent'")
    public void logoutEvent(LogoutEvent logoutEvent) {
        repository.delete(logoutEvent.getUser());

    }

}