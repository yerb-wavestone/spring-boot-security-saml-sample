package com.vdenotaris.spring.boot.security.saml.web.config;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app", ignoreUnknownFields = false)
public class ApplicationProperties {

	private final Saml saml = new Saml();

	public Saml getSaml() {
		return saml;
	}

	public static class Saml {

		private final RelayState relayState = new RelayState();

		private final Map<String, String> identityProviders = new LinkedHashMap<>();

		private final Context context = new Context();

		private String loginEndpoint;

		public RelayState getRelayState() {
			return relayState;
		}

		public Map<String, String> getIdentityProviders() {
			return identityProviders;
		}

		public Context getContext() {
			return context;
		}

		public String getLoginEndpoint() {
			return loginEndpoint;
		}

		public void setLoginEndpoint(String loginEndpoint) {
			this.loginEndpoint = loginEndpoint;
		}

		public static class RelayState {

			private String defaultValue;
			private String[] validPatterns;

			public String getDefaultValue() {
				return defaultValue;
			}

			public void setDefaultValue(String defaultValue) {
				this.defaultValue = defaultValue;
			}

			public String[] getValidPatterns() {
				return validPatterns;
			}

			public void setValidPatterns(String[] validPatterns) {
				this.validPatterns = validPatterns;
			}

		}

		public static class Context {

			private URI replacementUri;

			public URI getReplacementUri() {
				return replacementUri;
			}

			public void setReplacementUri(URI replacementUri) {
				this.replacementUri = replacementUri;
			}

		}

	}

}
