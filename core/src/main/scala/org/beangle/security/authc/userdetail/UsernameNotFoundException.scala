package org.beangle.security.authc.userdetail

import org.beangle.security.authc.BadCredentialsException

@SerialVersionUID(1L)
class UsernameNotFoundException(message:String,cause:Throwable=null) extends BadCredentialsException(message,cause) {

}
