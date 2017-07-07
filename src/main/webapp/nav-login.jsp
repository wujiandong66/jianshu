<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<nav class="navbar navbar-inverse navbar-fixed-top">
    <div class="container-fluid">
        <div class="navbar-header">
            <button class="navbar-toggle" data-toggle="collapse" data-target="#nav">
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">简书</a>
        </div>
        <div id="nav" class="collapse navbar-collapse">
            <ul class="nav navbar-nav">
                <li id="li-index" class="active"><a href="/">首页</a></li>
                <li><a href="">下载 APP</a></li>
            </ul>
            <ul class="nav navbar-nav navbar-right">
                <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="">
                        Aa
                        <span class="caret"></span>
                    </a>
                    <ul class="dropdown-menu">
                        <li class="set">
                            <img src="static/image/moon_fill.svg" alt="" width="15"> 夜间模式
                            <input type="checkbox" name="night-mode">
                        </li>
                        <li class="divider"></li>
                        <li></li>
                    </ul>
                </li>
                <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" style="padding: 9px;" href="">
                        <img class="img-circle"
                             style="border: 1px #9d9d9d solid;"
                             src="static/upload/${sessionScope.user.avatar}" alt="${sessionScope.user.nick}"
                             width="32">
                        <span class="caret"></span>
                    </a>
                    <ul class="dropdown-menu" style="font-size: 16px">
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-user"></span>我的主页</a></li>
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-bookmark"></span>收藏的文章</a></li>
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-heart"></span>喜欢的文章</a></li>
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-inbox"></span>我的钱包</a></li>
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-cog"></span>设置</a></li>
                        <li><a href="" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-list-alt"></span>帮助与反馈</a></li>
                        <li><a href="user?action=signOut" style="padding: 15px 0;"><span style="color: #ea6f5a; margin: 0 20px;" class="glyphicon glyphicon-log-out"></span>退出</a></li>
                    </ul>
                </li>
                <li>
                    <button id="write-note" class="btn btn-danger navbar-btn"><i class="glyphicon glyphicon-pencil"></i>
                        写文章
                    </button>
                </li>
            </ul>
            <form class="navbar-form navbar-left" action="" method="post">
                <div class="input-group">
                    <input class="form-control" type="text" name="keywords" placeholder="搜索">
                    <div class="input-group-btn">
                        <button class="btn btn-default">
                            <i class="glyphicon glyphicon-search"></i>
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</nav>