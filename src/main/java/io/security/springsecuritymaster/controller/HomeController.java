package io.security.springsecuritymaster.controller;


import io.security.springsecuritymaster.domain.dto.AccountDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
public class HomeController {
	@GetMapping(value="/")
	public String dashboard() {
		return "/dashboard";
	}

	@GetMapping(value="/user")
	public String user() {
		return "/user";
	}

	@GetMapping(value="/manager")
	public String manager() {
		return "/manager";
	}

	@GetMapping(value="/admin")
	public String admin() {
		return "/admin";
	}

	@GetMapping(value="/api")
	public String restDashboard() {
		return "rest/dashboard";
	}
}