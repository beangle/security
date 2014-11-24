package org.beangle.security.blueprint

import org.beangle.data.model.TemporalOn

object Scope extends Enumeration(0) {
  class Scope(name: String) extends super.Val(name)

  /** 不受保护的公共资源 */
  val Public = ScopeValue("Public")
  /** 受保护的公有资源 */
  val Protected = ScopeValue("Protected")
  /** 受保护的私有资源 */
  val Private = ScopeValue("Private")

  private def ScopeValue(name: String): Scope = {
    new Scope(name)
  }
}

trait FuncResource extends Resource {
  import Scope._
  def scope: Scope
}

trait FuncPermission extends Permission {
  override def resource: FuncResource
}