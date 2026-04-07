import org.beangle.parent.Dependencies.*
import org.beangle.parent.Settings.*

ThisBuild / organization := "org.beangle.security"
ThisBuild / version := "4.4.13-SNAPSHOT"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/beangle/security"),
    "scm:git@github.com:beangle/security.git"
  )
)

ThisBuild / developers := List(
  Developer(
    id = "chaostone",
    name = "Tihua Duan",
    email = "duantihua@gmail.com",
    url = url("http://github.com/duantihua")
  )
)

ThisBuild / description := "The Beangle Data Library"
ThisBuild / homepage := Some(url("https://beangle.github.io/security/index.html"))

val beangle_commons = "org.beangle.commons" % "beangle-commons" % "6.0.16"
val beangle_jdbc = "org.beangle.jdbc" % "beangle-jdbc" % "1.1.8"
val beangle_cache = "org.beangle.cache" % "beangle-cache" % "0.1.19"
val beangle_web = "org.beangle.web" % "beangle-web" % "0.7.6"
val beangle_serializer = "org.beangle.serializer" % "beangle-serializer" % "0.1.25"

lazy val root = (project in file("."))
  .settings(
    name := "beangle-security",
    common,
    Compile / mainClass := Some("org.beangle.security.realm.ldap.Main"),
    libraryDependencies ++= Seq(beangle_commons, beangle_cache, beangle_jdbc, beangle_web, slf4j, protobuf),
    libraryDependencies ++= Seq(logback_classic % "test", beangle_serializer % "test", scalatest, mockito)
  )
