package org.beangle.security.blueprint.service

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.blueprint.service.internal.FuncPermissionServiceImpl
import org.beangle.security.blueprint.service.internal.CachedDaoAuthorizer
import org.beangle.security.blueprint.service.internal.DaoUserRealm
import org.beangle.security.blueprint.service.internal.UserServiceImpl

class DefaultModule extends AbstractBindModule {

  protected override def binding(){
    bind(classOf[CachedDaoAuthorizer],classOf[FuncPermissionServiceImpl])
    bind(classOf[DaoUserRealm],classOf[UserServiceImpl])
  }
}