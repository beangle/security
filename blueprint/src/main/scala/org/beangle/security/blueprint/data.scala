package org.beangle.security.blueprint

import org.beangle.data.model.{ IntId, Named }

trait DataResource extends Resource

trait DataField extends IntId with Named {
  def title: String
  def resource: DataResource
  def typeName: String
}

trait DataPermission extends Permission {
  override def resource: DataResource
  def attrs: String
  def filters: String
}