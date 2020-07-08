/*
 * Copyright 2020 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */

package com.vdenotaris.spring.boot.security.saml.web.core;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {
	
	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);
	
	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		
		// The method is supposed to identify local account of user referenced by
		// data in the SAML assertion and return UserDetails object describing the user.
		
		String userID = credential.getNameID().getValue();
		
		LOG.info(userID + " is logged in");
		
		LOG.info(credential.getAttributes().size() + " attributes");
		for (final Attribute attr : credential.getAttributes()) {
			LOG.info("- " + attr.getName() + " = " + credential.getAttributeAsString(attr.getName()));
		}
		
		List<GrantedAuthority> authorities = new ArrayList<>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);
		if (hasSimpleAttribute(credential, "EmailAddress", "erb.wavestone@gmail.com")) {
			authorities.add(new SimpleGrantedAuthority("ROLE_YERB"));
		}
		if (hasSimpleAttribute(credential, "country", "NL")) {
			authorities.add(new SimpleGrantedAuthority("ROLE_NL"));
		}

		// In a real scenario, this implementation has to locate user in a arbitrary
		// dataStore based on information present in the SAMLCredential and
		// returns such a date in a form of application specific UserDetails object.
		return new User(userID, "<abc123>", true, true, true, true, authorities);
	}
	
	private boolean hasSimpleAttribute(final SAMLCredential credential, final String name, final String value) {
		return credential.getAttributes().stream().anyMatch(
				attr -> name.equals(attr.getName()) && value.equals(credential.getAttributeAsString(attr.getName())));
	}

}
