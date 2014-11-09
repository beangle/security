package org.beangle.security.blueprint

import org.beangle.data.model.{ Enabled, Hierarchical, IntIdEntity, Named }
import org.beangle.data.model.SlowId

trait MenuProfile extends IntIdEntity with Named with Enabled with SlowId {
  def menus: Seq[Menu]
  def role: Role
}

trait Menu extends IntIdEntity with Named with Enabled with Hierarchical[Menu] with SlowId {

  def title: String
  def entry: Option[FuncResource]
  def params: String
  def remark: String
  def resources: Seq[FuncResource]
}