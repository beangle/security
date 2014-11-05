package org.beangle.security.blueprint.domain

import org.beangle.data.model.bean.{ EnabledBean, HierarchicalBean, IntIdBean, NamedBean, UpdatedBean }
import org.beangle.security.blueprint.{ Field, Profile, Role, User }

class FieldBean extends IntIdBean with NamedBean with Field {
  var title: String = _
  var source: String = _
  var multiple: Boolean = _
  var required: Boolean = _
  var typeName: String = _
  var keyName: String = _
  var properties: String = _
}

class RoleBean extends IntIdBean with NamedBean with UpdatedBean with EnabledBean
  with HierarchicalBean[Role] with Profile with Role {
  var properties = new collection.mutable.HashMap[Field, String]
  var creator: User = _
  var remark: String = _
  override def getName: String = {
    name
  }
  def this(id: Int, name: String) {
    this()
    this.id = id
    this.name = name
  }
}

