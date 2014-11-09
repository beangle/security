package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.FuncResource
import org.beangle.security.blueprint.FuncPermission
import org.beangle.security.blueprint.Role
import org.beangle.security.blueprint.User

trait FuncPermissionService {

  def getResource(name: String): Option[FuncResource]

  def getResourceNamesByRole(roleId: Integer): Set[String]

  def getResources(user: User): Seq[FuncResource]

  def getPermissions(role: Role): Seq[FuncPermission]
}