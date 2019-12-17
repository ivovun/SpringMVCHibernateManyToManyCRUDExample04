package com.websystique.springmvc.dao;

import java.util.List;

import com.websystique.springmvc.model.User;

public interface UserDao {
	User findById(long id);
	
	User findBySSO(String sso);

//	void save(User user);

	void persist(User user);

	void update(User user);

	void deleteBySSO(String sso);
	
	List<User> findAllUsers();

}

