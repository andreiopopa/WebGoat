package org.owasp.webgoat.login;

import lombok.AllArgsConstructor;
import org.owasp.webgoat.users.WebGoatUser;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpCookie;
import java.util.List;

import static java.util.Optional.ofNullable;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@Component
@AllArgsConstructor
public class LoginHandler extends SimpleUrlAuthenticationSuccessHandler {

    private JmsTemplate jmsTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
        WebGoatUser user = (WebGoatUser) authentication.getPrincipal();
        ofNullable(httpServletResponse.getHeader("Set-Cookie")).ifPresent(c -> {
            List<HttpCookie> cookies = HttpCookie.parse(c);
            jmsTemplate.convertAndSend("webgoat", new LoginEvent(user.getUsername(), cookies.get(0).getValue()), m -> {
                        m.setStringProperty("type", LoginEvent.class.getSimpleName());
                        return m;
                    }
            );
        });
    }
}
