package com.spring.securityPractice.controller;

import com.spring.securityPractice.constants.AppConstants;
import com.spring.securityPractice.model.UserDto;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/account/show")
    public String accountShow(){
        return "Account show!";
    }
    @GetMapping("/account/create")
    public String accountCreate(){
        return "Create Account!";
    }
    @GetMapping("/account/delete")
    public String accountDelete(){
        return "Delete Account!";
    }
    @GetMapping("/account/edit")
    public String accountEdit(){
        return "Update your Account!";
    }
    @GetMapping("/account/addmoney")
    public String accountAddMoney(){
        return "Add Money in your Account!";
    }
    @GetMapping("/account/transfermoney")
    public String accountTransferMoney(){
        return "Transfer Money from your Account!";
    }

    @PostMapping("users/registration")
    public ResponseEntity<?> registerUser(@RequestBody UserDto userDto) {
        try {
            UserDto createdUser = userService.createUser(userDto);
            String accessToken = JWTUtils.generateToken(createdUser.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Sign-up Successful!!");
            response.put("user", createdUser);
            response.put(AppConstants.HEADER_STRING, AppConstants.TOKEN_PREFIX + accessToken);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }
}
