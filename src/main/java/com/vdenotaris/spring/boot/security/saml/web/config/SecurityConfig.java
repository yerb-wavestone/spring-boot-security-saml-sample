package com.vdenotaris.spring.boot.security.saml.web.config;

import static com.vdenotaris.spring.boot.security.saml.web.config.SecurityConstant.ROLE_NL;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import com.vdenotaris.spring.boot.security.saml.web.config.jwt.JwtAuthenticationFilter;
import com.vdenotaris.spring.boot.security.saml.web.config.jwt.JwtAuthenticationProvider;

/**
 * @author slemoine
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private static final String API = "yerApi";

	/**
	 * Rest security configuration for /jwt/api/
	 */
	@Configuration
	@Order(2)
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
	@Order(3)
	public static class JwtTokenSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/jwt/token";

		private final AuthenticationEntryPoint entryPoint;
		private final CsrfTokenRepository csrfTokenRepository;

		public JwtTokenSecurityConfig(final @Qualifier(API) AuthenticationEntryPoint entryPoint,
				final @Qualifier(API) CsrfTokenRepository csrfTokenRepository) {
			this.entryPoint = entryPoint;
			this.csrfTokenRepository = csrfTokenRepository;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(entryPoint);
			http.anonymous().disable();
			http.csrf().csrfTokenRepository(csrfTokenRepository);
			http.antMatcher(apiMatcher) //
					.authorizeRequests().anyRequest().hasAuthority(ROLE_NL);
		}
	}

	/**
	 * Rest security configuration for remaining endpoints
	 */
	@Configuration
	public static class SamlProtectedApiSecurityConfig extends WebSecurityConfigurerAdapter {

		private final AuthenticationEntryPoint entryPoint;
		private final CsrfTokenRepository csrfTokenRepository;

		public SamlProtectedApiSecurityConfig(final @Qualifier(API) AuthenticationEntryPoint entryPoint,
				final @Qualifier(API) CsrfTokenRepository csrfTokenRepository) {
			this.entryPoint = entryPoint;
			this.csrfTokenRepository = csrfTokenRepository;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(entryPoint);
			http.anonymous().disable();
			http.csrf().csrfTokenRepository(csrfTokenRepository);
			http.authorizeRequests().anyRequest().hasAuthority(ROLE_NL);
		}

	}

	@Bean
	@Qualifier(API)
	@Lazy
	public AuthenticationEntryPoint httpStatusEntryPointWithLocation(final ApplicationProperties props) {
		return (request, response, authException) -> {
			response.addHeader(HttpHeaders.LOCATION, props.getSaml().getLoginEndpoint());
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
		};
	}

	@Bean
	@Qualifier(API)
	@Lazy
	public CsrfTokenRepository readOnlyCsrfTokenRepository() {
		return new CsrfTokenRepository() {
			final CsrfTokenRepository delegate = CookieCsrfTokenRepository.withHttpOnlyFalse();

			@Override
			public void saveToken(final CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
				// don't save
			}

			@Override
			public CsrfToken loadToken(HttpServletRequest request) {
				return delegate.loadToken(request);
			}

			@Override
			public CsrfToken generateToken(HttpServletRequest request) {
				return delegate.generateToken(request);
			}

		};
	}

	/**
	 * Saml security config
	 */
	@Configuration
	@Import(SamlSecurityConfig.class)
	public static class SamlConfig {

	}

}
