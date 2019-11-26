#justauth-spring-security-starter

##简介
spring security 认证实质是添加了一系列的Filter进行认证。所以此项目也是开发了一个Filter，并放在了认证链上的最后的位置。<br/>
此项目基于 <a href="https://github.com/justauth/JustAuth">justauth</a>开发的认证并嫁接到 spring security 的认证上。<br/>
功能：
    <ul>
        <li>未认证用户经第三方认证后走认证流程</li>
        <li>已认证用户经第三方认证后走注册流程</li>
        <li>查看用户绑定记录</li>
        <li>解绑用户</li>
    </ul>
    注意：目前系统内只实现了github、gitee、google
###使用
#### 自定义服务

##### 自定义 JustauthAuthenticationService
```
@Slf4j
public class WjwJustauthAuthenticationService<A> extends AbstractJustauthAuthenticationService<AuthUser> {

    public WjwJustauthAuthenticationService(String providerId, AuthRequestFactory factory) {
        super(providerId, factory);
    }
}
```

##### AuthenticationFailureHandler 配置
```
@Component
public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        if (exception instanceof JustauthAuthenticationRedirectException) {
            response.sendRedirect(((JustauthAuthenticationRedirectException) exception).getRedirectUrl());
            return;
        }
        response.setContentType("application/json;charset=UTF-8");
        Result result = Result.error(new BusinessException(BusinessExCodeEnum.LOGIN_ERROR));
        JSONObject json = new JSONObject(result);
        response.getWriter().write(json.toJSONString(0));
    }
}
```
##### WebSecurityConfigurer 配置
```
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {
    @Autowired
    AuthRequestFactory factory;

    @Autowired
    DataSource dataSource;

    @Autowired(required = false)
    private TextEncryptor encryptor;
    
    @Bean
    protected UsersConnectionRepository jdbcUsersConnectionRepository() {
        return new JdbcUsersConnectionRepository(dataSource, encryptor);
    }
     @Override
     protected void configure(HttpSecurity http) throws Exception {
        http...;
           JustAuthSocialConfigurer justauth = new JustAuthSocialConfigurer(factory, jdbcUsersConnectionRepository());
        //        justauth.setUsersConnectionRepository(jdbcUsersConnectionRepository());
                justauth.setUserDetailsService(sysUserService);
                justauth.setAuthenticationFailureHandler(authenticationFailureHandler);
                justauth.setAuthenticationSuccessHandler(authenticationSuccessHandler);
                justauth.addJustauthAuthenticationService("wjw", new WjwJustauthAuthenticationService("wjw", factory));
                http.apply(justauth);
     }
}
```

##### application.yml 配置
```
justauth:
  enabled: true
  type:
    github:
      client-id: 323a5*********297b
      client-secret: 380************32f33
      redirect-uri: http://********/justauth/github
    google:
      client-id: 15330************.apps.googleusercontent.com
      client-secret: gCzAl*************9sH
      redirect-uri: http://********/justauth/google
    gitee:
      client-id: 12f1d90************431db5c65d850d
      client-secret: ac29e60632*************be25cfc6d6e5ae2811e
      redirect-uri: http://********/justauth/gitee
  extend:
    enumClass: com.luoqiz.test.justauth.AuthCustomSource
    config:
      wjw:
        request-class: com.luoqiz.test.justauth.AuthWjwRequest
        client-id: Y***********A
        client-secret: d00955f*************3005fcd109
        redirect-uri: http://test.luoqiz.top/justauth/wjw
```

