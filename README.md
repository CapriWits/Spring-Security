# README

---

> 本项目基于`SpringBoot 2.0.9.RELEASE`版本， `JDK1.8` 开发
>
> 其他依赖版本请看 pom.xml 文件即可。

- 本项目主要内容为 登录、注销和根据权限展现动态表单，基于Spring-Security 实现。
- 登录账号密码在 config/SecurityConfig配置类 中可自定义
- 因为只是Spring Security学习Demo，没加上持久层的Dao编写，账号密码都固定写好的，仅供测试。

-  前端就不在此展示了，自行拉取跑一下就是了，主要是 Security 的后端 Demo 学习



### SpringSecurity 简介

满足：

- 功能权限
- 访问权限
- 菜单权限

不依赖框架，则要手动写 拦截器，过滤器，出现大量原生代码，冗余。

Apache Shiro 也是常见的 安全框架，SpringSecurity 完美兼容 SpringBoot，重点学习。



### 环境搭建

- 导入 `static` 里面的 `js` `css`.
- 导入 `templates` 里面的 `index.html` `level1 - 3`分别表示三种不同的权限，后面对权限加以控制。然后就是登录界面 `login.html`
- 导入 `pom.xml`依赖

```XML
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
<!--    thymeleaf    -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<!--    spring-boot-starter-security    -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<!--    thymeleaf整合spring security-->
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-springsecurity5</artifactId>
    <version>3.0.4.RELEASE</version>
</dependency>
```

- `thymeleaf-extras-springsecurity5`是thymeleaf整合security的，官方的文档使用的是 `jsp`(老古董)。

- `application.properties`中关闭themeleaf缓存，便于测试

```properties
#关闭缓存
spring.thymeleaf.cache=false
```



- 到此基本的环境搭建完成，编写`RouterController`完成页面跳转，看能否正常进入对应页面跳转，用来检验环境搭建正常。



### SecurityConfig安全配置类

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
}
```

- @EnableWebSecurity 开启WebSecurity模式
- WebSecurityConfigurerAdapter：自定义Security策略
- AuthenticaitonManagerBuilder：自定义人认证策略

Spring Security 两个主要目标是**“认证”**和**“授权”**(访问控制)。

认证：**Authentication**

授权：**Authorization**

> 官方文档：https://docs.spring.io/spring-security/site/docs/5.5.0-SNAPSHOT/reference/html5/#introduction



#### 授权：

```java
protected void configure(HttpSecurity http) throws Exception
```

- 该方法进行授权，将权限绑定到对应页面上去，这里给三个level文件夹下的文件绑定 3 种权限

```java
http.authorizeRequests()
        .antMatchers("/").permitAll()
        .antMatchers("/level1/**").hasRole("vip1")
        .antMatchers("/level2/**").hasRole("vip2")
        .antMatchers("/level3/**").hasRole("vip3");
```

- 采用链式编程。
- `permitAll()`开放全部权限，所有人可访问，一般就是首页。
- `hasRole()`进行授权命名。



```java
http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");
```

- `formLogin()`登录。查看源码上面的文档注释

> @Override
> 	   	protected void configure(HttpSecurity http) throws Exception {
> 	   		http.authorizeRequests().antMatchers("/**").hasRole("USER").and().formLogin()
> 	   				.usernameParameter("username") // default is username
> 	   				.passwordParameter("password") // default is password
> 	   				.loginPage("/authentication/login") // default is /login with an HTTP get
> 	   				.failureUrl("/authentication/login?failed") // default is /login?error
> 	   				.loginProcessingUrl("/authentication/login/process"); // default is /login
> 	   																		// with an HTTP
> 	   																		// post
> 	   	}

- 前端`<input>`对用name属性值默认为`username`，如果要修改则使用 `usernameParameter(newUsrName)`
- 前端`<input>`对用name属性值默认为`password`，如果要修改则使用 `passwordParameter(newPwd)`
- 默认登录路径为 `/login`，`loginProcessingUrl(diyUrl)`自定义登录路径。
- `loginPage`更改 Get 请求的登录界面。
- `failureUrl`更改登陆失败的界面。default：`/login?error`



```java
http.csrf().disable();
```

- CSRF:跨站请求伪造，Spring Security默认开启，可能会引起登出失败



```java
http.logout().logoutSuccessUrl("/"); 
```

- `logout()`实现注销功能。
- `logoutSuccessUrl()` 指定成功注销后跳到哪个页面



```java
http.rememberMe().rememberMeParameter("remember");
```

- 开启 "记住我" 功能 cookie默认保存两周
- `rememberMeParameter`更改前端 “记住我” checkbox 的 name 属性值。



#### 认证：

```java
protected void configure(AuthenticationManagerBuilder auth) throws Exception
```

- 用于认证，一般就是从数据库查询信息，然后倒回来认证。

```java
auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()) //添加密码编码器，增加安全性，下列的密码都要编码
        .withUser("cwh").password(new BCryptPasswordEncoder().encode("123123")).roles("vip2", "vip3")
        .and()  // 用 and 进行连接
        .withUser("root").password(new BCryptPasswordEncoder().encode("123123")).roles("vip1", "vip2", "vip3")
        .and()
        .withUser("guest").password(new BCryptPasswordEncoder().encode("123123")).roles("vip1");
```

- 链式编程
- `BCryptPasswordEncoder`密码编码器，推荐使用的一种，也有其他的编码器，详细请看`public interface PasswordEncoder`的实现类。
- `roles()`添加上认证。



### 前端代码

```html
xmlns:sec="http://www.thymeleaf.org/extras/spring-security"
```

- 加上security命名空间



```
sec:authorize="!isAuthenticated()"
```

- 是否认证



```
sec:authorize="hasRole('vip1')
```

- 判断是否有该角色（有权限）



> 最后感谢：KuangStudy