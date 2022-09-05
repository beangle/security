import org.beangle.parent.Dependencies._
import org.beangle.parent.Settings._

ThisBuild / organization := "org.beangle.security"
ThisBuild / version := "4.3.0"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/beangle/security"),
    "scm:git@github.com:beangle/security.git"
  )
)

ThisBuild / developers := List(
  Developer(
    id    = "chaostone",
    name  = "Tihua Duan",
    email = "duantihua@gmail.com",
    url   = url("http://github.com/duantihua")
  )
)

ThisBuild / description := "The Beangle Data Library"
ThisBuild / homepage := Some(url("https://beangle.github.io/security/index.html"))

val beangle_common_ver="5.4.0"
val beangle_data_ver="5.5.0"
val beangle_serializer_ver="0.1.0"
val beangle_cache_ver="0.1.0"
val beangle_web_ver="0.2.0"
val beangle_commons_core = "org.beangle.commons" %% "beangle-commons-core" % beangle_common_ver
val beangle_data_jdbc = "org.beangle.data" %% "beangle-data-jdbc" % beangle_data_ver
val beangle_serializer_protobuf = "org.beangle.serializer"  %% "beangle-serializer-protobuf" % beangle_serializer_ver

val beangle_cache_api = "org.beangle.cache" %% "beangle-cache-api" %  beangle_cache_ver
val beangle_web_servlet = "org.beangle.web" %% "beangle-web-servlet" % beangle_web_ver
val commonDeps = Seq(beangle_commons_core, logback_classic, logback_core, scalatest, beangle_web_servlet)

lazy val root = (project in file("."))
  .settings()
  .aggregate(core,cas,session,web)

lazy val core = (project in file("core"))
  .settings(
    name := "beangle-security-core",
    common,
    libraryDependencies ++= commonDeps
  )

lazy val session = (project in file("session"))
  .settings(
    name := "beangle-security-session",
    common,
    libraryDependencies ++= (commonDeps ++ Seq(beangle_cache_api,beangle_data_jdbc,beangle_serializer_protobuf))
  ).dependsOn(core)

lazy val web = (project in file("web"))
  .settings(
    name := "beangle-security-web",
    common,
    libraryDependencies ++= (commonDeps ++ Seq(beangle_web_servlet))
  ).dependsOn(core)

lazy val cas = (project in file("cas"))
  .settings(
    name := "beangle-security-cas",
    common,
    libraryDependencies ++= (commonDeps ++ Seq(mockito))
  ).dependsOn(web)

publish / skip := true
