package org.beangle.security.blueprint

import org.beangle.data.model.{ Enabled, Hierarchical, IntIdEntity, Named }

trait MenuProfile extends IntIdEntity with Named with Enabled {
  def menus: Seq[Menu]
}

trait Menu extends IntIdEntity with Named with Enabled with Hierarchical[Menu] with Ordered[Menu] {
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