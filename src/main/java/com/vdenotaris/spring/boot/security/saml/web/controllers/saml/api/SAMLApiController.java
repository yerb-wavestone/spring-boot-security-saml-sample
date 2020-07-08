package com.vdenotaris.spring.boot.security.saml.web.controllers.saml.api;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author slemoine
 */
@RestController
@RequestMapping("/saml/api/mycontroller")
public class SAMLApiController {

	@GetMapping
	public ResponseEntity<?> getValue(final Authentication auth) {
		return ResponseEntity.ok(auth.getPrincipal());
	}

}