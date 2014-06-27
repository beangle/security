package org.beangle.security.blueprint.domain

import org.beangle.data.model.{IntIdEntity, Named}

trait DataResource extends Resource

trait DataField extends IntIdEntity with Named{
  def title: String
  def resource: DataResource
  def typeName: String
}

trait DataPermission extends Permission{
  override def resource: DataResource
  def attrs:String
  def filters:String
}