package com.websystique.springmvc.dao;

import org.springframework.stereotype.Repository;

import com.websystique.springmvc.model.UserProfile;


//@Repository("userProfileDao")
@Repository
public class UserProfileDaoImpl extends AbstractDao<Long, UserProfile>implements UserProfileDao{

	public UserProfile findById(long id) {
		return getByKey(id);
	}

	public UserProfile findByType(String type) {
		return findByFieldName("type", type);
	}
}
