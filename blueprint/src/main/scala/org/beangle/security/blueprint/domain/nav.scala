package org.beangle.security.blueprint.domain

import org.beangle.data.model.{ Enabled, Hierarchical, IntIdEntity, Named }
import org.beangle.data.model.IdGrowSlow

trait MenuProfile extends IntIdEntity with Named with Enabled with IdGrowSlow {
  def menus: Seq[Menu]
  def role: Role
}

trait Menu extends IntIdEntity with Named with Enabled with Hierarchical[Menu] with IdGrowSlow {

  def title: String
  def entry: Option[FuncResource]
  def params: String
  def remark: String
  def resources: Seq[FuncResource]
}