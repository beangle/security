package org.beangle.security.blueprint.domain.model

import org.beangle.data.model.bean.{EnabledBean, HierarchicalBean, IntIdBean, NamedBean}
import org.beangle.security.blueprint.domain.{FuncResource, Menu, MenuProfile, Role}

class MenuProfileBean extends IntIdBean with NamedBean with EnabledBean with MenuProfile {
  var menus = new collection.mutable.ListBuffer[Menu]
  var role: Role = _
}

class MenuBean extends IntIdBean with NamedBean with EnabledBean with HierarchicalBean[Menu] with Menu {
  var title: String = _
  var entry: Option[FuncResource] = None
  var params: String = _
  var remark: String = _
  var resources = new collection.mutable.ListBuffer[FuncResource]
}