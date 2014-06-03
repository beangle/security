package org.beangle.security.session

import org.beangle.security.authc.AuthenticationException

class SessionException(msg: String, principal: Any) extends AuthenticationException(msg, principal) {
}

class OvermaxSessionException(val maxUserLimit: Int, principal: Any)
  extends SessionException(String.valueOf(maxUserLimit), principal) {
}
