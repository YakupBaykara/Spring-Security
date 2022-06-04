package com.course.springSecurity.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.course.springSecurity.security.ApplicationUserRole;
import com.google.common.collect.Lists;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}

	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
			new ApplicationUser(
				ApplicationUserRole.STUDENT.getGrantedAuthorities(),
				passwordEncoder.encode("password"),
				"annaSmith",
				true,
				true,
				true,
				true
			),
			
			new ApplicationUser(
				ApplicationUserRole.ADMIN.getGrantedAuthorities(),
				passwordEncoder.encode("password"),
				"linda",
				true,
				true,
				true,
				true
			),
			
			new ApplicationUser(
				ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
				passwordEncoder.encode("password"),
				"tom",
				true,
				true,
				true,
				true
			)
			
	    );
		
		return applicationUsers;
	}
}
