package com.websystique.springmvc.dao;

import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

public abstract class AbstractDao<PK extends Serializable, T> {
	private final Class<T> persistentClass;

	@PersistenceContext
	EntityManager entityManager;
	
	@SuppressWarnings("unchecked")
	public AbstractDao(){
		this.persistentClass =(Class<T>) ((ParameterizedType) this.getClass().getGenericSuperclass()).getActualTypeArguments()[1];
	}

	public T getByKey(PK key) {
		return entityManager.find(persistentClass, key);
	}

	public void persist(T entity) {
		entityManager.persist(entity);
	}

	public void update(T entity) {
		entityManager.merge(entity);
	}

	public void delete(T entity) {
		entityManager.remove(entity);
	}

	public List<T> findAll() {
		return entityManager.createQuery("from " + persistentClass.getName()).getResultList();
	}

	public T findByFieldName(String name, String value) {
		try {
			return (T) entityManager.createQuery("SELECT e FROM " + persistentClass.getName()
					+" e WHERE e." + name + " = :name").setParameter("name", value).getSingleResult();
		} catch (NoResultException e) {
			return null;
		}
	}
}
