package com.example.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewsController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
    @GetMapping("/home")
    public String home() {
        return "home";
    }
    @GetMapping("/")
    public String index() {
        return "hello";
    }
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
