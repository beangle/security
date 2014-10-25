package org.beangle.security.blueprint.domain

import org.beangle.data.model.TemporalOn
import org.beangle.data.model.SlowId

object Scope extends Enumeration(0) {
  type Scope = Value
  /** 不受保护的公共资源 */
  val Public = Value("Public")
  /** 受保护的公有资源 */
  val Protected = Value("Protected")
  /** 受保护的私有资源 */
  val Private = Value("Private")
}

trait FuncResource extends Resource {
  import Scope._
  def scope: Scope
}

trait FuncPermission extends Permission {
  override def resource: FuncResource
}