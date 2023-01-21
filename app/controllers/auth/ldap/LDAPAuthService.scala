package controllers.auth.ldap

import java.util.Hashtable

import com.google.inject.Inject
import com.sun.jndi.ldap.LdapCtxFactory
import controllers.auth.AuthService
import javax.naming._
import javax.naming.directory.SearchControls
import play.api.{Configuration, Logger}

import scala.util.control.NonFatal
import java.{util => ju}

class LDAPAuthService @Inject()(globalConfig: Configuration) extends AuthService {

  private val log = Logger(this.getClass)

  private final val config = new LDAPAuthConfig(globalConfig.get[Configuration]("auth.settings"))

  def checkUserAuth(username: String, password: String): Boolean = {
    val props = new Hashtable[String, String]()
    props.put(Context.SECURITY_PRINCIPAL, config.userTemplate.format(username, config.baseDN))
    props.put(Context.SECURITY_CREDENTIALS, password)

    try {
      LdapCtxFactory.getLdapCtxInstance(config.url, props)
      true
    } catch {
      case e: AuthenticationException =>
        log.info(s"login of $username failed with: ${e.getMessage}")
        false
      case NonFatal(e) =>
        log.error(s"login of $username failed", e)
        false
    }
  }

  def checkUserAuthWithDn(dn: String, password: String): Boolean = {
    val props = new Hashtable[String, String]()
    props.put(Context.SECURITY_PRINCIPAL, dn)
    props.put(Context.SECURITY_CREDENTIALS, password)

    try {
      LdapCtxFactory.getLdapCtxInstance(config.url, props)
      true
    } catch {
      case e: AuthenticationException =>
        log.info(s"login of $dn failed with: ${e.getMessage}")
        false
      case NonFatal(e) =>
        log.error(s"login of $dn failed", e)
        false
    }
  }

  def checkUserAuthWithGroupSearch(username: String, password: String, groupConfig: LDAPGroupSearchConfig): Boolean = {
    val props = new Hashtable[String, String]()
    props.put(Context.SECURITY_PRINCIPAL, groupConfig.bindDN)
    props.put(Context.SECURITY_CREDENTIALS, groupConfig.bindPwd)
    props.put(Context.REFERRAL, "follow")
    val user     = groupConfig.userAttrTemplate.format(username, config.baseDN)
    val controls = new SearchControls()
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    try {
      val context = LdapCtxFactory.getLdapCtxInstance(config.url, props)
      val filter = s"(& (${groupConfig.userAttr}=$user)(${groupConfig.group}))"
      val search = context.search(groupConfig.baseDN, filter, controls)
      context.close()
      if (!search.hasMore())
        return false
      
      var dn = search.next().getNameInNamespace()
      if (dn.isEmpty())
        return false

      if (!this.checkUserAuthWithDn(dn, password))
        return false

      return true
    } catch {
      case e: AuthenticationException =>
        log.info(s"User $username doesn't fulfill condition (${groupConfig.group}) : ${e.getMessage}")
        false
      case NonFatal(e) =>
        log.error(s"Unexpected error while checking group membership of $username", e)
        false
    }
  }

  def auth(username: String, password: String): Option[String] = {
    val isValidUser = config.groupMembership match {
      case Some(groupConfig) => checkUserAuthWithGroupSearch(username, password, groupConfig)
      case None              => checkUserAuth(username, password)
    }
    if (isValidUser) Some(username) else None
  }

}
