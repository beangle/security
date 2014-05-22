package org.beangle.security.session

import org.beangle.security.authc.AuthenticationException

@SerialVersionUID(-2827989849698493720L)
class SessionException(msg: String) extends AuthenticationException(msg) {
}


@SerialVersionUID(-2827989849698493720L)
class OvermaxSessionException(val maxUserLimit: Int) extends SessionException(String.valueOf(maxUserLimit)) {
}
