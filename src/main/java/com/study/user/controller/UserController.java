package com.study.user.controller;

import com.study.user.dto.entity.User;
import com.study.user.dto.form.UserAddForm;
import com.study.user.dto.vo.ResultVo;
import com.study.user.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/info")
    public ResultVo getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        ResultVo<Authentication> resultVo = new ResultVo();
        resultVo.setData(authentication);
        return resultVo;
    }

    @PostMapping
    public ResultVo add(@RequestBody UserAddForm form) {
        boolean add = userService.add(form);
        return ResultVo.success(add);
    }

}
