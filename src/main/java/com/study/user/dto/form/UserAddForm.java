package com.study.user.dto.form;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserAddForm {

    private String username;

    private String password;
}
