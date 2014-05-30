package org.beangle.security.web.context

import org.beangle.security.context.SecurityContextBean
import org.beangle.security.mgt.SecurityManager
import javax.servlet.http.HttpServletRequest

class WebSecurityContext(val request:HttpServletRequest,securityManager: SecurityManager) extends SecurityContextBean(securityManager) {

}