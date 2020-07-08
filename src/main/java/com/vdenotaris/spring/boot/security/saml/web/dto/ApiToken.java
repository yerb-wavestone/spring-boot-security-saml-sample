package com.vdenotaris.spring.boot.security.saml.web.dto;


import java.io.Serializable;

@SuppressWarnings("serial")
public class ApiToken implements Serializable {

    private String token;

    public ApiToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
