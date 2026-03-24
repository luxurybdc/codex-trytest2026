package com.example.auth.controller;

import com.example.auth.config.JwtAuthFilter;
import com.example.auth.model.LoginRequest;
import com.example.auth.model.RegisterRequest;
import com.example.auth.service.UserService;
import com.example.auth.util.JwtUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Controller
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/")
    public String home(Model model, javax.servlet.http.HttpServletRequest request) {
        Object loginUser = request.getAttribute("loginUser");
        model.addAttribute("username", loginUser == null ? "未知用户" : loginUser.toString());
        return "home";
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("form", new RegisterRequest());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("form") RegisterRequest form,
                           BindingResult bindingResult,
                           Model model) {
        if (bindingResult.hasErrors()) {
            return "register";
        }

        boolean success = userService.register(form.getUsername(), form.getPassword());
        if (!success) {
            model.addAttribute("error", "用户名已存在");
            return "register";
        }
        model.addAttribute("msg", "注册成功，请登录");
        model.addAttribute("form", new LoginRequest());
        return "login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("form", new LoginRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@Valid @ModelAttribute("form") LoginRequest form,
                        BindingResult bindingResult,
                        HttpServletResponse response,
                        Model model) {
        if (bindingResult.hasErrors()) {
            return "login";
        }

        boolean ok = userService.authenticate(form.getUsername(), form.getPassword());
        if (!ok) {
            model.addAttribute("error", "用户名或密码错误");
            return "login";
        }

        String token = jwtUtil.generateToken(form.getUsername());
        Cookie cookie = new Cookie(JwtAuthFilter.JWT_COOKIE_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie(JwtAuthFilter.JWT_COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
        return "redirect:/login";
    }
}
