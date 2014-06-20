package org.beangle.security.web

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.web.access.SecurityFilter
import org.beangle.security.web.access.HttpMethodPermissionFilter
import org.beangle.security.mgt.DefaultSecurityManager
import org.beangle.security.session.MemSessionRegistry
import org.beangle.security.authc.RealmAuthenticator
import org.beangle.security.authz.DefaultAuthorizer
import org.beangle.security.session.DefaultSessionBuilder
import org.beangle.security.web.access.DefaultAccessDeniedHandler
import org.beangle.security.session.SessionRegistry
import org.beangle.security.web.access.AccessDeniedHandler

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind(classOf[SecurityFilter]).constructor(list(classOf[HttpMethodPermissionFilter]), ?, ?, ?).shortName

    bind(classOf[DefaultSecurityManager], classOf[RealmAuthenticator], classOf[DefaultAuthorizer])

    bind(classOf[MemSessionRegistry], classOf[DefaultSessionBuilder])

    bind(classOf[UrlEntryPoint]).constructor("/login")

    //FIXME
    bind(classOf[DefaultAccessDeniedHandler]).constructor("/error")
  }
}