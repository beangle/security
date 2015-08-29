package org.beangle.security.authz

object Resource {
  /** 资源的所有部分 */
  final val AllParts = "*";

  /** 允许所有操作 */
  final val AllActions = "*";
}

trait Resource extends Serializable {
  def title: String
  def actions: String
  def remark: String
  def name: String
  def enabled: Boolean
}

object Scopes extends Enumeration(0) {
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
