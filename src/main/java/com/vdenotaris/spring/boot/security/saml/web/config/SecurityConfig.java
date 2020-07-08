package com.vdenotaris.spring.boot.security.saml.web.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import com.vdenotaris.spring.boot.security.saml.web.config.jwt.JwtAuthenticationFilter;
import com.vdenotaris.spring.boot.security.saml.web.config.jwt.JwtAuthenticationProvider;

/**
 * @author slemoine
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private static final String APP = "yer";

	/**
	 * Rest security configuration for /jwt/api/
	 */
	@Configuration
	@Order(1)
	public static class JwtProtectedApiSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/jwt/api/**";

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.addFilterBefore(new JwtAuthenticationFilter(apiMatcher, super.authenticationManager()),
					UsernamePasswordAuthenticationFilter.class);
			http.antMatcher(apiMatcher) //
					.authorizeRequests().anyRequest().authenticated();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			auth.authenticationProvider(new JwtAuthenticationProvider());
		}

	}

	/**
	 * Rest security configuration for /jwt/token
	 */
	@Configuration
	@Order(2)
	public static class JwtTokenSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/jwt/token";

		private final AuthenticationEntryPoint entryPoint;
		private final CsrfTokenRepository csrfTokenRepository;

		public JwtTokenSecurityConfig(final @Qualifier(APP) AuthenticationEntryPoint entryPoint,
				final CsrfTokenRepository csrfTokenRepository) {
			this.entryPoint = entryPoint;
			this.csrfTokenRepository = csrfTokenRepository;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(entryPoint);
//            http.csrf().csrfTokenRepository(tokenRepository).requireCsrfProtectionMatcher(req -> true);
			http.antMatcher(apiMatcher) //
					.authorizeRequests().anyRequest().authenticated();
			// TODO role
		}
	}

	/**
	 * Rest security configuration for /saml/api/
	 */
	@Configuration
	@Order(3)
	public static class SamlProtectedApiSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/saml/api/**";

		private final AuthenticationEntryPoint entryPoint;
		private final CsrfTokenRepository csrfTokenRepository;

		public SamlProtectedApiSecurityConfig(final @Qualifier(APP) AuthenticationEntryPoint entryPoint,
				final CsrfTokenRepository csrfTokenRepository) {
			this.entryPoint = entryPoint;
			this.csrfTokenRepository = csrfTokenRepository;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(entryPoint);
//			http.anonymous().disable();
//            http.csrf().disable();
			http.antMatcher(apiMatcher) //
					.authorizeRequests().anyRequest().authenticated();
			// TODO role
		}

	}

	@Bean
	@Qualifier(APP)
	@Lazy
	public AuthenticationEntryPoint httpStatusEntryPointWithLocation(final ApplicationProperties props) {
		return (request, response, authException) -> {
			response.addHeader(HttpHeaders.LOCATION, props.getSaml().getLoginEndpoint());
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
		};
	}

	@Bean
	@Lazy
	public CsrfTokenRepository csrfTokenRepository() {
		return CookieCsrfTokenRepository.withHttpOnlyFalse();
	}

	/**
	 * Saml security config
	 */
	@Configuration
	@Import(SamlSecurityConfig.class)
	public static class SamlConfig {

	}

}
