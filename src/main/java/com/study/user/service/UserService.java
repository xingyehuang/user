package com.study.user.service;

import com.study.user.dto.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;
import com.study.user.dto.form.UserAddForm;

/**
 * @author 邢烨煌
 * @description 针对表【t_user(用户表)】的数据库操作Service
 * @createDate 2023-06-24 22:34:28
 */
public interface UserService extends IService<User> {

    /**
     * 添加用户
     *
     * @param userAddForm
     * @return
     */
    boolean add(UserAddForm userAddForm);
}
