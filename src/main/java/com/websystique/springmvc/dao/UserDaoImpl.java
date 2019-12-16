package com.websystique.springmvc.dao;

import java.util.List;

import org.hibernate.Hibernate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import com.websystique.springmvc.model.User;

@Repository("userDao")
public class UserDaoImpl extends AbstractDao<Long, User> implements UserDao {
	static final Logger logger = LoggerFactory.getLogger(UserDaoImpl.class);
	
	public User findById(long id) {
		User user = getByKey(id);
		if(user!=null){
			Hibernate.initialize(user.getUserProfiles());
		}
		return user;
	}

	public User findBySSO(String sso) {
		return findByFieldName("ssoId", sso);
	}

	public List<User> findAllUsers() {
		return findAll();
	}

	public void save(User user) {
		if (user.getId() == null) {
			persist(user);
		} else {
			update(user);
		}
	}

	public void deleteBySSO(String sso) {
		delete(findBySSO(sso));
	}
}
