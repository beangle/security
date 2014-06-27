package org.beangle.security.blueprint.domain.model

import java.security.Principal

import org.beangle.data.model.bean.{EnabledBean, IntIdBean, NamedBean, TemporalAtBean}
import org.beangle.security.blueprint.domain.{FuncPermission, FuncResource, Role, Scope}

class FuncResourceBean extends IntIdBean with NamedBean with EnabledBean with FuncResource {
  var scope = Scope.Public
  var title: String = _
  var actions: String = _
  var remark: String = _
}

class FuncPermissionBean extends IntIdBean with TemporalAtBean with FuncPermission {
  var role: Role = _
  var resource: FuncResource = _
  var actions: String = _
  var restrictions: String = _
  var remark: String = _

  def principal: Principal = role
}
