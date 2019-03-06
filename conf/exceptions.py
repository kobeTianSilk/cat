# coding=utf-8
from applications.http import HTTPError


class CatException(Exception):
    """一个基础异常模块"""
    pass


class RouteError(CatException):
    """自定义路由异常模块"""


class RouteReset(CatException):
    """如果由插件或请求处理程序引发，则路由重置和所有插件。"""


class RouterUnknownModeError(RouteError):
    pass


class RouteSyntaxError(RouteError):
    """不知道路由规则异常模块"""


class RouteBuildError(RouteError):
    """当前路由模块没有被建立"""


class ParamsError(CatException):
    """参数异常模块"""


class TemplateError(HTTPError):
    """模板加载异常"""
    def __init__(self, message):
        HTTPError.__init__(self, 500, message)
