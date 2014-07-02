package org.beangle.security.blueprint.service.internal

import org.beangle.security.blueprint.service.FuncPermissionService
import org.beangle.data.model.dao.GeneralDao
import org.beangle.security.blueprint.domain.FuncResource
import org.beangle.data.jpa.dao.OqlBuilder
import org.beangle.security.authz.GrantedAuthority
import org.beangle.security.authz.Authorizer
import org.beangle.security.blueprint.service.FuncPermissionService
import org.beangle.security.authz.GrantedAuthority
import org.beangle.security.blueprint.service.FuncPermissionService
import org.beangle.security.authz.GrantedAuthority
import org.beangle.security.context.SecurityContext
import org.beangle.security.blueprint.service.FuncPermissionService
import org.beangle.security.authc.Account
import org.beangle.commons.cache.Cache
import org.beangle.security.blueprint.domain.Scope
import org.beangle.security.authz.Authority
import org.beangle.commons.cache.CacheManager
import org.beangle.security.blueprint.domain.FuncPermission

class FuncPermissionServiceImpl(val entityDao: GeneralDao) extends FuncPermissionService {
  def getResource(name: String): Option[FuncResource] = {
    val query = OqlBuilder.from(classOf[FuncResource], "r")
    query.where("r.name=:name", name).cacheable()
    val rs = entityDao.search(query)
    if (rs.isEmpty) None else Some(rs.head)
  }

  def getResourceNamesByRole(roleId: Integer): Set[String] = {
    val hql = "select a.resource.name from " + classOf[FuncPermission].getName() +
      " as a where a.role.id= :roleId and a.resource.enabled = true"
    val query = OqlBuilder.hql(hql).param("roleId", roleId).cacheable()
    entityDao.search(query).toSet.asInstanceOf[Set[String]]
  }
}

class CachedDaoAuthorizer(permissionService: FuncPermissionService, cacheManager: CacheManager) extends Authorizer {
  var unknownIsPublic = true

  var cache: Cache[Authority, Set[String]] = cacheManager.getCache("dao-authorizer-cache")

  def isPermitted(principal: Any, resource: Any, operation: Any): Boolean = {
    val resourceName = resource.toString
    val rscOption = permissionService.getResource(resourceName)
    if (rscOption.isEmpty) return unknownIsPublic
    rscOption.get.scope match {
      case Scope.Public => true
      case Scope.Protected => principal != SecurityContext.Anonymous
      case _ => principal != SecurityContext.Anonymous && principal.asInstanceOf[Account].authorities.exists { role => isAuthorized(role, resourceName) }
    }
  }

  //FIXME change resource name to id
  private def isAuthorized(authority: Authority, resource: String): Boolean = {
    cache.get(authority) match {
      case Some(actions) => actions.contains(resource)
      case None =>
        val newActions = permissionService.getResourceNamesByRole(authority.authority.asInstanceOf[Integer])
        cache.put(authority, newActions)
        newActions.contains(resource)
    }
  }

}