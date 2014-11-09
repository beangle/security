package org.beangle.security.blueprint

import org.beangle.data.model.{ IntIdEntity, Named }
import org.beangle.data.model.SlowId

trait DataResource extends Resource

trait DataField extends IntIdEntity with Named with SlowId {
  def title: String
  def resource: DataResource
  def typeName: String
}

trait DataPermission extends Permission {
  override def resource: DataResource
  def attrs: String
  def filters: String
}