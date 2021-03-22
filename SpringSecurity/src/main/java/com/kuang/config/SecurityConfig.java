package com.kuang.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 授权
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页有相应权限才能访问
        //链式编程
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限，默认到登录页面，formLogin源码文档注释有说默认的路径是怎样的
        //loginPage定制登录页面
        http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");

        //跨站请求伪造，springsecurity默认开启，可能会引起登出失败
        http.csrf().disable(); // 防CSRF攻击关闭
        //注销功能
        http.logout().logoutSuccessUrl("/");    // logoutSuccessUrl 指定成功注销后跳到哪个页面
        //开启 "记住我" 功能 cookie默认保存两周
        http.rememberMe().rememberMeParameter("remember");

    }

    /**
     * 认证
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()) //添加密码编码器，增加安全性，下列的密码都要编码
                .withUser("cwh").password(new BCryptPasswordEncoder().encode("123123")).roles("vip2", "vip3")
                .and()  // 用 and 进行连接
                .withUser("root").password(new BCryptPasswordEncoder().encode("123123")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123123")).roles("vip1");

        //There is no PasswordEncoder mapped for the id "null"  报错要加上密码编译器
    }
}
