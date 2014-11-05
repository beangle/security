package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.FuncResource

trait FuncPermissionService {

  def getResource(name: String): Option[FuncResource]

  def getResourceNamesByRole(roleId: Integer): Set[String]
}