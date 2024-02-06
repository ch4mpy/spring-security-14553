package com.example.demo;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

@SpringBootApplication
public class Demo14524Application {

	public static void main(String[] args) {
		SpringApplication.run(Demo14524Application.class, args);
	}

	@Configuration
	static class SecurityConfiguration {
		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE - 1)
		SecurityWebFilterChain clientSecurityFilterChain(
				ServerHttpSecurity http,
				ReactiveClientRegistrationRepository clientRegistrationRepository,
				@Value("${client-with-login-routes}") List<String> clientRoutes,
				@Value("${client-permit-all}") List<String> permitAll) {
			final var clientPathMatchers =
					clientRoutes.stream().map(PathPatternParserServerWebExchangeMatcher::new).map(ServerWebExchangeMatcher.class::cast).toList();
			http.securityMatcher(new OrServerWebExchangeMatcher(clientPathMatchers));
			// @formatter:off
			http.authorizeExchange((authorize) -> authorize
					.pathMatchers(permitAll.toArray(new String[] {})).permitAll()
					.anyExchange().authenticated());
			// @formatter:on
			http.oauth2Login(Customizer.withDefaults());
			http.logout((logout) -> {
				logout.logoutSuccessHandler(new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository));
			});
			http.oidcLogout((logout) -> {
				logout.backChannel(Customizer.withDefaults());
			});

			return http.build();
		}

		@Bean
		@Order(Ordered.LOWEST_PRECEDENCE)
		SecurityWebFilterChain permitAllSecurityFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http.authorizeExchange((authorize) -> authorize.anyExchange().permitAll());
			// @formatter:on
			http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
			http.csrf(csrf -> csrf.disable());

			return http.build();
		}
	}

}
