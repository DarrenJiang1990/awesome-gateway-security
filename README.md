# spring cloud gateway和spring security 集成的完整入门例子
# 引言

&emsp;&emsp;由于目前网上大部分spring security的集成都是基于传统的spring servlet机制，而spring cloud gateway 采用webflux作为底层web技术支持，不支持servlet，笔者在集成的过程中走了很多弯路，所以特地写一篇spring cloud gateway和security的集成实践博客，如有错误，欢迎指正。
# Spring Security
&emsp;&emsp;spring security 为spring提供了一套web安全性的完整框架，主要包含用户认证和用户授权。在用户认证方面，Spring Security 支持主流的验证方式，包括HttpBasic、Http表单认证、Http摘要认证、OpenId(如Oauth)和LDAP。本文实现的功能是gateway网关集成security，前端利用form表单进行登陆认证后返回基于一个用户名和密码的加密串，后续前端调用其他接口需利用httpbasic携带加密串的方式进行认证和授权。
# 技术环境

 - [x] jdk 1.8
 - [x] spring-boot 2.1.4.RELEASE
 - [x] spring-cloud Greenwich.RELEASE
 
# 集成步骤
 (1)创建spring boot工程，引入cloud gateway 和security 的jar包依赖，核心依赖包如图:
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630160934692.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
注意:cloud gateway 不能和spring-web混合使用，cloud gateway采用的webflux技术，不能再引入spring-web包。

(2)编写securtiy的核心认证授权配置
 &emsp;&emsp;如下，创建security的核心安全配置类SecurityConfig并自定义SecurityWebFilterChain，在webflux环境下要生效必须用注解@EnableWebFluxSecurity使其生效:
 

```
@EnableWebFluxSecurity
public class SecurityConfig {


    //security的鉴权排除的url列表
    private static final String[] excludedAuthPages = {
            "/auth/login",
            "/auth/logout",
            "/health",
            "/api/socket/**"
    };

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http
                .authorizeExchange()
                .pathMatchers(excludedAuthPages).permitAll()  //无需进行权限过滤的请求路径
                .pathMatchers(HttpMethod.OPTIONS).permitAll() //option 请求默认放行
                .anyExchange().authenticated()
                .and()
                .httpBasic()
                .and()
                .formLogin() //启动页面表单登陆,spring security 内置了一个登陆页面/login
                .and().csrf().disable()//必须支持跨域
                .logout().disable();

        return http.build();
    }
}
```
&emsp;&emsp;配置文件中添加以下security的用户名和密码，访问受权限保护的页面即会进入security的登陆认证页面，只有输入配置的用户名和密码后才能继续访问其他页面。

```
#security 配置
spring.security.user.name=admin
spring.security.user.password=123456
```
&emsp;&emsp;配置后，启动spring boot 程序，输入需授权的url，则会弹出以下页面，用户名密码输入登陆成功后即可正常访问其他受保护页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630161225660.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
注:此功能为spring security 内置的formLogin默认基于用户名和密码的认证授权(表单登陆)功能，需开启formLogin()功能。
# 高阶用法
&emsp;&emsp;现在项目开发都是前后端分离模式，对于前后端分离security的默认配置则不能满足认证和授权的需求。下面讲解前端通过form的login表单ajax提交给网关security的认证接口，认证成功后security在响应header中返回基于username:password的base64加密串token，后续前端再调用其他接口需基于http basci的安全机制进行授权(即在header中添加Authorization=basic token，spring security在收到请求后通过ServerHttpBasicAuthenticationConverter解析用户认证信息，决定是否授权通过。
主要修改如下:
(1)自定义用户认证逻辑

```
@Bean
SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) throws Exception {
    http
            .authorizeExchange()
            .pathMatchers(excludedAuthPages).permitAll()  //无需进行权限过滤的请求路径
            .pathMatchers(HttpMethod.OPTIONS).permitAll() //option 请求默认放行
            .anyExchange().authenticated()
            .and()
            .httpBasic()
            .and()
            .formLogin().loginPage("/auth/login")
            .authenticationSuccessHandler(authenticationSuccessHandler) //认证成功
            .authenticationFailureHandler(authenticationFaillHandler) //登陆验证失败
            .and().exceptionHandling().authenticationEntryPoint(customHttpBasicServerAuthenticationEntryPoint)  //基于http的接口请求鉴权失败
            .and() .csrf().disable()//必须支持跨域
            .logout().disable();

    return http.build();
}


@Bean
public PasswordEncoder passwordEncoder() {
    return  NoOpPasswordEncoder.getInstance(); //默认不加密
}
```
&emsp;&emsp;security默认认证响应信息为text/html，前后端分离一般返回json，此处自定义了认证成功和失败的响应处理、鉴权失败时的处理。
&emsp;&emsp;认证成功处理器authenticationSuccessHandler，继承security对gateway支持的认证成功处理器WebFilterChainServerAuthenticationSuccessHandler,并覆盖其onAuthenticationSuccess方法，本例中认证成功在请求头中返回Authorization(用户名和密码的base加密信息)，代码如下:

```
@Component
public class AuthenticationSuccessHandler extends WebFilterChainServerAuthenticationSuccessHandler   {

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication){
        ServerWebExchange exchange = webFilterExchange.getExchange();
        ServerHttpResponse response = exchange.getResponse();
        //设置headers
        HttpHeaders httpHeaders = response.getHeaders();
        httpHeaders.add("Content-Type", "application/json; charset=UTF-8");
        httpHeaders.add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        //设置body
        WsResponse wsResponse = WsResponse.success();
       byte[]   dataBytes={};
        ObjectMapper mapper = new ObjectMapper();
        try {
            User user=(User)authentication.getPrincipal();
            AuthUserDetails userDetails=buildUser(user);
            byte[] authorization=(userDetails.getUsername()+":"+userDetails.getPassword()).getBytes();
            String token= Base64.getEncoder().encodeToString(authorization);
            httpHeaders.add(HttpHeaders.AUTHORIZATION, token);
            wsResponse.setResult(userDetails);
            dataBytes=mapper.writeValueAsBytes(wsResponse);
        }
        catch (Exception ex){
            ex.printStackTrace();
            JsonObject result = new JsonObject();
            result.addProperty("status", MessageCode.COMMON_FAILURE.getCode());
            result.addProperty("message", "授权异常");
            dataBytes=result.toString().getBytes();
        }
        DataBuffer bodyDataBuffer = response.bufferFactory().wrap(dataBytes);
        return response.writeWith(Mono.just(bodyDataBuffer));
    }



    private AuthUserDetails  buildUser(User user){
        AuthUserDetails userDetails=new AuthUserDetails();
        userDetails.setUsername(user.getUsername());
        userDetails.setPassword(user.getPassword().substring(user.getPassword().lastIndexOf("}")+1,user.getPassword().length()));
        return userDetails;
    }
```
&emsp;&emsp;其中AuthUserDetails 为security维护的用户信息接口UserDetails的自定义实现类，封装了用户账户和权限信息.

&emsp;&emsp;认证失败处理器authenticationFaillHandler,实现ServerAuthenticationFailureHandler并覆盖其onAuthenticationFailure自定义认证失败的处理逻辑，本例中仅返回认证失败的响应信息:

```
@Component
public class AuthenticationFaillHandler  implements ServerAuthenticationFailureHandler {

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException e) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        ServerHttpResponse response = exchange.getResponse();
        //设置headers
        HttpHeaders httpHeaders = response.getHeaders();
        httpHeaders.add("Content-Type", "application/json; charset=UTF-8");
        httpHeaders.add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        //设置body
        WsResponse<String> wsResponse = WsResponse.failure(MessageCode.COMMON_AUTHORIZED_FAILURE);
        byte[]   dataBytes={};
        try {
            ObjectMapper mapper = new ObjectMapper();
            dataBytes=mapper.writeValueAsBytes(wsResponse);
        }
        catch (Exception ex){
            ex.printStackTrace();
        }
        DataBuffer bodyDataBuffer = response.bufferFactory().wrap(dataBytes);
        return response.writeWith(Mono.just(bodyDataBuffer));
    }
}
```
&emsp;&emsp;认证成功后访问新的接口需在请求头中添加基于httpbasic的认证鉴权信息，服务端收到请求后通过识别为httpbasic的鉴权信息，通过ServerHttpBasicAuthenticationConverter提取用户名和密码后进行鉴权，鉴权通过放行请求。
&emsp;&emsp;此处自定义鉴权失败时的处理逻辑CustomHttpBasicServerAuthenticationEntryPoint，只需继承默认的httpbasic鉴权失败处理器HttpBasicServerAuthenticationEntryPoint并覆盖其commence方法即可:

```
@Component
public class CustomHttpBasicServerAuthenticationEntryPoint extends HttpBasicServerAuthenticationEntryPoint /* implements ServerAuthenticationEntryPoint */{


    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String DEFAULT_REALM = "Realm";
    private static String WWW_AUTHENTICATE_FORMAT = "Basic realm=\"%s\"";
    private String headerValue = createHeaderValue("Realm");
    public CustomHttpBasicServerAuthenticationEntryPoint() {
    }



    public void setRealm(String realm) {
        this.headerValue = createHeaderValue(realm);
    }

    private static String createHeaderValue(String realm) {
        Assert.notNull(realm, "realm cannot be null");
        return String.format(WWW_AUTHENTICATE_FORMAT, new Object[]{realm});
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().add("Content-Type", "application/json; charset=UTF-8");
            response.getHeaders().set(HttpHeaders.AUTHORIZATION, this.headerValue);
            JsonObject result = new JsonObject();
            result.addProperty("status", MessageCode.COMMON_AUTHORIZED_FAILURE.getCode());
            result.addProperty("message", MessageCode.COMMON_AUTHORIZED_FAILURE.getMsg());
            byte[] dataBytes=result.toString().getBytes();
            DataBuffer bodyDataBuffer = response.bufferFactory().wrap(dataBytes);
            return response.writeWith(Mono.just(bodyDataBuffer));
    }
}
```
&emsp;&emsp;由于security在认证时必须采用一种密码加密方式，在security5中默认的BCryptPasswordEncoder是随机盐的加密方式，且删除了原有低版本的md5的encoder，所以此处需配置不加密模式，即NoOpPasswordEncoder，在后续用户查找逻辑时可添加自定义的用户密码加密规则，只需和前端规则一致即可。

(2)定义用户查找逻辑
&emsp;&emsp;security 的认证和授权都离不开系统中的用户，实际用户都来自db，本例中采用的是系统配置的默认用户。
&emsp;&emsp;UserDetailsRepositoryReactiveAuthenticationManager作为security的核心认证管理器，并调用userDetailsService去查找用户，本集成环境中自定义用户查找逻辑需实现ReactiveUserDetailsService接口并覆盖findByUsername（通过用户名查找用户）方法，核心代码如下:

```
@Component
public class SecurityUserDetailsService implements ReactiveUserDetailsService {

     @Value("${spring.security.user.name}")
     private   String userName;

    @Value("${spring.security.user.password}")
    private   String password;


    @Override
    public Mono<UserDetails> findByUsername(String username) {
       //todo 预留调用数据库根据用户名获取用户
        if(StringUtils.equals(userName,username)){
            UserDetails user = User.withUsername(userName)
                  .password(MD5Encoder.encode(password,username))
                    .roles("admin").authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("admin"))
                    .build();
            return Mono.just(user);
        }
        else{
            return Mono.error(new UsernameNotFoundException("User Not Found"));

        }

    }



}
```

说明:为避免密码在系统中明文传输，前端传入的密码通过md5加盐username的方式传入后台，所以security用户查找逻辑也需要对配置的密码做统一的处理,固此处加入了md5加密工具。
(3)其他扩展
&emsp;&emsp;security 和webflux的集成核心是AuthenticationWebFilter 过滤器，可查看此过滤器关联的内部接口自定义逻辑。
&emsp;&emsp;httpbasic认证方式的核心配置在ServerHttpSecurity中HttpBasicSpec的configure方法
# 集成效果展示
1.用户在前端输入用户名和加密后的密码后以表单方式提交给formlogin认证接口:
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630162127504.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
 可以看到认证成功后响应header中有Authorization信息:
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630162140926.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
 2.访问新的鉴权的接口只需在header中添加基于Authorization的httpbasic认证信息:
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630162201964.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
 如果输入错误的httpbasic 用户认证信息:
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20190630162231986.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01vbmdvbGlhbldvbGY=,size_16,color_FFFFFF,t_70)
 # 参考资料
 

 - https://www.jb51.net/article/140429.htm 
 - https://www.naturalprogrammer.com/blog/18149/reactive-spring-security-webflux-rest-web-services
 - https://www.sudoinit5.com/post/spring-reactive-auth-forms/#customized-webflux-form-authentication
 - https://blog.csdn.net/Dongguabai/article/details/80932225
 - https://docs.spring.io/spring-security/site/docs/current/reference/html5/#jc-webflux
 - spring security的用户名密码验证规则:  https://blog.csdn.net/qq924862077/article/details/83027033
 - https://github.com/eugenp/tutorials/tree/master/spring-5-reactive-security
