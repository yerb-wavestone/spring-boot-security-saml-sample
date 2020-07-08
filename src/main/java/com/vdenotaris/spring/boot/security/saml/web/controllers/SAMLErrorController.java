package com.vdenotaris.spring.boot.security.saml.web.controllers;

import java.time.LocalDateTime;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SAMLErrorController {

	@RequestMapping("/saml-error.html")
	public String error(HttpServletRequest request, Model model) {
		model.addAttribute("timestamp", LocalDateTime.now());
		Throwable throwable = (Throwable) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		if (throwable != null) {
			model.addAttribute("error", throwable.getClass().getName());
			model.addAttribute("trace", Stream.of(throwable.getStackTrace()).map(StackTraceElement::toString)
					.collect(Collectors.joining("\n")));
		}
		return "saml-error";
	}

}