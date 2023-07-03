package com.study.user.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <a>Title: HelloWorldController </a>
 * <a>Author: Kapcb <a>
 * <a>Description: HelloWorldController <a>
 *
 * @author Kapcb
 * @version 1.0
 * @date 2022/6/12 22:05
 * @since 1.0
 */
@RestController
public class HelloWorldController {

    @GetMapping("index")
    public String index() {
        return "login success!";
    }

    @GetMapping("hello")
    public String hello() {
        return "Hello, World!";
    }

}


