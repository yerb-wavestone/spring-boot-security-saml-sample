package com.vdenotaris.spring.boot.security.saml.web.controllers.jwt;

import org.joda.time.DateTime;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vdenotaris.spring.boot.security.saml.web.config.SecurityConstant;
import com.vdenotaris.spring.boot.security.saml.web.dto.ApiToken;

/**
 * @author slemoine
 */
@RestController
@RequestMapping("/jwt/token")
public class AuthController {

	@GetMapping
	public ApiToken token() throws JOSEException {

		final DateTime dateTime = DateTime.now();

		// build claims
		JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
		jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(120).toDate());
		jwtClaimsSetBuilder.claim("APP", "SAMPLE");

		// signature
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
		signedJWT.sign(new MACSigner(SecurityConstant.JWT_SECRET));

		return new ApiToken(signedJWT.serialize());
	}

}
