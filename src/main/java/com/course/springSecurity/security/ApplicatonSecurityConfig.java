package com.course.springSecurity.security;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.course.springSecurity.auth.ApplicationUserService;
import com.course.springSecurity.jwt.JwtConfig;
import com.course.springSecurity.jwt.JwtTokenVerifier;
import com.course.springSecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  // Annotation ların kullanılacağı belirtilir. @PreAuthorize annotation
public class ApplicatonSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final SecretKey secretKey;
	private final JwtConfig jwtConfig;
	
	@Autowired
	public ApplicatonSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
			SecretKey secretKey, JwtConfig jwtConfig) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
/*			(Cross Site Request Forgery. Disable olmazsa Post, Put, Delete işlemleri için cookie olarak gelen X-XSRF-TOKEN Headers lara eklenerek işlem yapılır.)
			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and()
*/			
			.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // JWT token STATELESS olduğu için
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
			.addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // Bunu yaparak şifreye gerek kalmadan herkesin index.html i görmesini sağlıyoruz.
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) // Sadece student olanlar görebilir.

/*			(ANNOTATİON LAR EKLENDİĞİ İÇİN GEREK KALMADI)
			.antMatchers(HttpMethod.POST, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())         
			.antMatchers(HttpMethod.DELETE, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())		
			.antMatchers(HttpMethod.PUT, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())			
			.antMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name()) // Burada olması önemli! 
*/			
			.anyRequest()
			.authenticated();

//			.and()
			
/*			(BASİC AUTHENTİCATİON)
			.httpBasic(); 							  // Basic authentication için. Logout yapılamıyor.
*/

/*			(FORM BASİC AUTHENTİCATİON)
  			.formLogin() 							  // Form Basic Authentication. Logout yapılabiliyor.
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses", true)      // Login den sonra yönelndirilecek URL
				.passwordParameter("password")			  // login.html de password name ile aynı
				.usernameParameter("username")			  // login.html de username name ile aynı
			.and()
			.rememberMe()                             //SESSIONID 30 dakika geçerli. Remember me default olarak 14 güne uzatır.
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("somethingverysecure")
				.rememberMeParameter("remember-me")		  // login.html de remember-me9839+ name ile aynı
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))    // csrf disable olduğu için yazıyoruz.
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")  // Tarayıcı konsolunda Application kısmında yer alır.
				.logoutSuccessUrl("/login");
	*/
	}
	
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

/* IN MEMORY 
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails annaSmithUser = User.builder()
				.username("annasmith")
				.password(passwordEncoder.encode("password"))
//				.roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT         // Kullanıcılara otoriteler tanımlandıktan sonra
				.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())  // Kullanıcılara otoriteler tanımlandıktan sonra
				.build();
		
		UserDetails lindaUser = User.builder()
				.username("linda")
				.password(passwordEncoder.encode("password"))
//				.roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN              // Kullanıcılara otoriteler tanımlandıktan sonra
				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())     // Kullanıcılara otoriteler tanımlandıktan sonra
				.build();
		
		UserDetails tomUser = User.builder()
				.username("tom")
				.password(passwordEncoder.encode("password"))
//				.roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE    // Kullanıcılara otoriteler tanımlandıktan sonra
				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())  // Kullanıcılara otoriteler tanımlandıktan sonra
				.build();
		
		return new InMemoryUserDetailsManager(
				annaSmithUser,
				lindaUser,
				tomUser
				);
	}
*/	
	

}
