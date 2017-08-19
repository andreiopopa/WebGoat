package org.owasp.webwolf.requests;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webwolf.WebGoatUser;
import org.springframework.boot.actuate.trace.Trace;
import org.springframework.boot.actuate.trace.TraceRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

import static java.util.Optional.empty;
import static java.util.Optional.of;

/**
 * Keep track of all the incoming requests, we are only keeping track of request originating from
 * WebGoat and only if there is a cookie (otherwise we can never relate it back to a user).
 *
 * @author nbaars
 * @since 8/13/17.
 */
@Slf4j
public class WebWolfTraceRepository implements TraceRepository {

    private final String webGoatPort;
    private final Map<String, ConcurrentLinkedDeque<Trace>> cookieTraces;
    private final IMap<String, String> userSessions;

    public WebWolfTraceRepository(String webGoatPort, HazelcastInstance hazelcastInstance) {
        this.webGoatPort = webGoatPort;
        this.cookieTraces = hazelcastInstance.getMap("cookieTraces");
        this.userSessions = hazelcastInstance.getMap("userSessions");
    }

    @Override
    public List<Trace> findAll() {
        HashMap<String, Object> map = Maps.newHashMap();
        map.put("nice", "Great you found the standard Spring Boot tracing endpoint!");
        Trace trace = new Trace(new Date(), map);
        return Lists.newArrayList(trace);
    }

    public List<Trace> findTraceForUser(String username) {
        return Lists.newArrayList(cookieTraces.getOrDefault(username, new ConcurrentLinkedDeque<>()));
    }

    @Override
    public void add(Map<String, Object> map) {
        Optional<String> host = getFromHeaders("host", map);
        String path = (String) map.getOrDefault("path", "");
        if (host.isPresent()  && ("/".equals(path) || path.contains("challenge"))) {
            Optional<Cookie> cookie = getFromHeaders("cookie", map).map(c -> of(new Cookie(c))).orElse(empty());
            cookie.ifPresent(c -> {
                Optional<String> user = determineUser(c);
                user.ifPresent(u -> {
                    ConcurrentLinkedDeque<Trace> traces = this.cookieTraces.getOrDefault(u, new ConcurrentLinkedDeque<>());
                    traces.addFirst(new Trace(new Date(), map));
                    cookieTraces.put(u, traces);
                });

            });
        }
    }

    private Optional<String> determineUser(Cookie cookieIncomingRequest) {
        //Request from WebGoat to WebWolf will contain the session cookie of WebGoat try to map it to a user
        //this mapping is added to userSession by the CookieFilter in WebGoat code
        Optional<Map.Entry<String, String>> userEntry = this.userSessions.entrySet().stream().filter(e -> new Cookie(e.getValue()).equals(cookieIncomingRequest)).findFirst();
        Optional<String> user = userEntry.map(e -> e.getKey());

        if (!user.isPresent()) {
            //User is maybe logged in to WebWolf use this user
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof WebGoatUser) {
                WebGoatUser wg = (WebGoatUser) authentication.getPrincipal();
                user = of(wg.getUsername());
            }
        }
        return user;
    }


    private Optional<String> getFromHeaders(String header, Map<String, Object> map) {
        Map<String, Object> headers = (Map<String, Object>) map.get("headers");
        if (headers != null) {
            Map<String, Object> request = (Map<String, Object>) headers.get("request");
            if (request != null) {
                return Optional.ofNullable((String) request.get(header));
            }
        }
        return Optional.empty();
    }
}
