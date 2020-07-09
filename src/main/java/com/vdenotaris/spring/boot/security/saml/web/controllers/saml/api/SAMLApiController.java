package com.vdenotaris.spring.boot.security.saml.web.controllers.saml.api;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author slemoine
 */
@RestController
@RequestMapping("/saml/api/mycontroller")
public class SAMLApiController {

	private static final String HEADER_NAME = "X-XSRF-TOKEN";

	@GetMapping
	public ResponseEntity<?> getValue(final Authentication auth,
			final @RequestHeader(name = HEADER_NAME, required = false) Optional<String> csrfToken) {
		return ResponseEntity.ok(Map.of(HEADER_NAME, csrfToken.orElse("<empty>"), "userDetails", auth.getDetails()));
	}

	@PostMapping
	public ResponseEntity<?> doSomething(
			final @RequestHeader(name = HEADER_NAME, required = false) Optional<String> csrfToken) {
		if (csrfToken.isEmpty()) {
			return ResponseEntity.badRequest().body(Map.of("message", HEADER_NAME + " is required"));
		}
		return ResponseEntity.ok(Map.of(HEADER_NAME, csrfToken.orElse("<empty>")));
	}

}