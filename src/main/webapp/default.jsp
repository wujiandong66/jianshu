
<!DOCTYPE html>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>简书 - 创作你的创作</title>
    <link rel='shortcut icon' type='image/x-icon' href='favicon.ico'>
    <link rel="stylesheet" href="static/css/bootstrap.min.css">
    <link rel="stylesheet" href="static/css/bootstrap-switch.min.css">
    <style>
        @import "static/css/nav.css";
    </style>
    <script src="static/js/jquery.min.js"></script>
    <script src="static/js/bootstrap.min.js"></script>
    <script src="static/js/bootstrap-switch.min.js"></script>
    <script src="static/js/nav.js"></script>
</head>
<body>
<c:if test="${sessionScope.user eq null}">
    <c:import url="nav.jsp"/>
</c:if>
<c:if test="${sessionScope.user ne null}">
    <c:import url="nav-login.jsp"/>
</c:if>
<div class="container">
    <h1>首页</h1>
    <small class="text-danger">${requestScope.message}</small>
    <small class="text-danger">${param.message}</small>
</div>
</body>
</html>