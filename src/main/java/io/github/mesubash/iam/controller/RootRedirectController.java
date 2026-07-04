package io.github.mesubash.iam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RootRedirectController {

    @GetMapping("/")
    public String redirectToHealth() {
        return "redirect:/actuator/health";
    }
}
