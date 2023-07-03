package com.study.user.dto.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResultVo<T> {

    private String code;
    private String message;
    private T data;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public static <T> ResultVo<T> success(T data){
        ResultVo<T> resultVo = ResultVo.<T>builder().build();
        resultVo.setData(data);
        resultVo.setMessage("登录成功");
        resultVo.setCode("200");
        return resultVo;
    }
}
