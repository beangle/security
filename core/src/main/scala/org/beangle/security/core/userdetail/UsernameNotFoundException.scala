package org.beangle.security.core.userdetail

import org.beangle.security.auth.BadCredentialsException

@SerialVersionUID(1L)
class UsernameNotFoundException(message:String,cause:Throwable=null) extends BadCredentialsException(message,cause) {

}
