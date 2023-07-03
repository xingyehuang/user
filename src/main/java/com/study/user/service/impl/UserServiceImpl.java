package com.study.user.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.study.user.dto.entity.User;
import com.study.user.dto.form.UserAddForm;
import com.study.user.service.UserService;
import com.study.user.mapper.UserMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

/**
* @author 邢烨煌
* @description 针对表【t_user(用户表)】的数据库操作Service实现
* @createDate 2023-06-24 22:34:28
*/
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
    implements UserService{

    @Override
    public boolean add(UserAddForm userAddForm) {
        Long count = lambdaQuery().eq(User::getUsername, userAddForm.getUsername()).count();
        Assert.isTrue(count == 0,"用户已存在");
        User user = new User();
        BeanUtils.copyProperties(userAddForm,user);
        return save(user);
    }
}




