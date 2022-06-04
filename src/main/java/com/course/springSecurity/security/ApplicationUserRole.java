package com.course.springSecurity.security;

import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.google.common.collect.Sets;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,
						  ApplicationUserPermission.COURSE_WRITE,
						  ApplicationUserPermission.STUDENT_READ,
						  ApplicationUserPermission.STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,
			  					 ApplicationUserPermission.STUDENT_READ));

	private final Set<ApplicationUserPermission> permissions;

	ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	// Getter Method
	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
		
	public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
		Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
						.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
						.collect(Collectors.toSet());
		permissions.add(new SimpleGrantedAuthority("ROLE_" +this.name()));
		return permissions;
	}
}
