package org.beangle.security.blueprint

import org.beangle.data.model.{ Enabled, Hierarchical, IntIdEntity, Named, SlowId }

trait MenuProfile extends IntIdEntity with Named with Enabled with SlowId {
  def menus: Seq[Menu]
  def role: Role
}

trait Menu extends IntIdEntity with Named with Enabled with Hierarchical[Menu] with Ordered[Menu] with SlowId {
  def profile: MenuProfile
  def title: String
  def entry: FuncResource
  def params: String
  def remark: String
  def resources: collection.Set[FuncResource]

  override def compare(other: Menu): Int = {
    indexno.compareTo(other.indexno)
  }
}