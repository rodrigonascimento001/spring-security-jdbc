package com.br.rodrigo.springsecjdbc.springsecurityjdbc.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SampleController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home(String username) {
        System.out.println(username);
        return "home";
    }

    @GetMapping("/403")
    public String denied(){
        return "denied";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminPage(SecurityContextHolderAwareRequestWrapper request){
        boolean b = request.isUserInRole("ROLE_ADMIN");
        System.out.println("ROLE_ADMIN=" + b);

        boolean c = request.isUserInRole("ROLE_USER");
        System.out.println("ROLE_USER=" + c);

        return "adminpage";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
