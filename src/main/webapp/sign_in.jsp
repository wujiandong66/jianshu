
<!DOCTYPE html>
<%@ page contentType='text/html;charset=UTF-8' language='java' %>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>登录 - 简书</title>
    <link rel='shortcut icon' type='image/x-icon' href='favicon.ico'>
    <link rel='stylesheet' href='static/css/bootstrap.min.css'>
    <link rel='stylesheet' href='static/css/bootstrap-switch.min.css'>
    <style>
        @import 'static/css/nav.css';
    </style>
    <style>
        body {
            background: #f1f1f1;
        }

        #logo {
            margin-bottom: 15px;
        }

        h3 a {
            display: inline-block;
            margin: 30px 10px;
        }

        #sign-in {
            color: #ea6f5a;
        }

        #form-box {
            border-radius: 5px;
            box-shadow: 1px 1px 1px #0f0f0f;
        }

        #form-box {
            background: #fff;
            padding: 50px;
        }

        #form-box div {
            margin-top: 15px;
        }

        #form-box button {
            margin: 30px 0 15px;
        }

        #mobile-message,
        #password-message {
            display: none;
        }

        #kaptchaImg {
            cursor: pointer;
        }
    </style>
    <script src='static/js/jquery.min.js'></script>
    <script src='static/js/bootstrap.min.js'></script>
    <script src='static/js/bootstrap-switch.min.js'></script>
    <script src='static/js/nav.js'></script>
    <script>
        var isMobileValidated; // 手机号通过了验证
        var isPasswordValidated; // 密码通过了验证
        var isKaptchaValidated; // 密码通过了验证

        function showMessage(element, text, removedClass, addedClass) {
            element.parent()
                .removeClass(removedClass[0])
                .addClass(addedClass[0]);
            element.parent().next('small')
                .text(text)
                .removeClass(removedClass[1])
                .addClass(addedClass[1])
                .fadeIn('slow');
        }


        function validateMobile() {
            var mobile = $('#mobile');
            if (mobile.val().length === 0) {
                showMessage(
                    mobile,
                    '请输入手机号或邮箱',
                    ['has-success', 'text-success'],
                    ['has-error', 'text-danger']
                );
                isMobileValidated = false;
            } else {
                isMobileValidated = true;
            }
        }

        function validatePassword() {
            var password = $('#password');
            if (password.val().length === 0) {
                showMessage(
                    password,
                    '请输入密码',
                    ['has-success', 'text-success'],
                    ['has-error', 'text-danger']
                );
                isPasswordValidated = false;
            } else {
                isPasswordValidated = true;
            }
        }

        function validateKaptcha() {
            var kaptcha = $('#kaptcha');
            if (kaptcha.val().length === 0) {
                showMessage(
                    kaptcha,
                    '请输入验证码',
                    ['has-success', 'text-success'],
                    ['has-error', 'text-danger']
                );
                isKaptchaValidated = false;
            } else {
                isKaptchaValidated = true;
            }
        }

        $(function () {
            $('#li-index').removeClass('active');
            $('#li-sign-in').addClass('active');

            $('#sign-in-form').submit(function () {
                validateMobile();
                validatePassword();
                validateKaptcha();
                return isMobileValidated && isPasswordValidated && isKaptchaValidated;
            });

            $('#mobile').focus(function () {
                showMessage(
                    $(this),
                    '',
                    ['has-error', 'text-danger'],
                    []
                );
            });

            $('#password').focus(function () {
                showMessage(
                    $(this),
                    '',
                    ['has-error', 'text-danger'],
                    []
                );
            });

            var kaptcha = $('#kaptcha');
            kaptcha.focus(function () {
                showMessage(
                    kaptcha,
                    '',
                    ['has-error', 'text-danger'],
                    []
                );
            });

            $('#kaptchaImg').click(function () {
                $(this)
                    .hide()
                    .attr('src', '/kaptcha.jpg?' + Math.floor(Math.random() * 100))
                    .fadeIn();
            });

            kaptcha.blur(function () {
                $.ajax({
                    url: 'user',
                    type: 'post',
                    data: {'action': 'checkValidCode', 'kaptchaReceived': kaptcha.val()},
                    dataType: 'json',
                    success: function (result) {
                        if (result.isValid) {
                            showMessage(
                                kaptcha,
                                '验证码正确',
                                ['has-error', 'text-danger'],
                                ['has-success', 'text-success']
                            );
                        } else {
                            showMessage(
                                kaptcha,
                                '验证码错误',
                                ['has-success', 'text-success'],
                                ['has-error', 'text-danger']
                            );
                        }
                    }
                });
            });
        });
    </script>
</head>
<body>
<%@ include file='nav.jsp' %>
<div class='container'>
    <div id='logo'><img src='static/image/logo.png' alt='简书'></div>
    <div id='form-box' class='col-md-4 col-md-offset-4'>
        <h3 class='text-center'>
            <a id="sign-in" href='sign_in.jsp'>登录</a> · <a id='sign-up' class="text-muted" href='sign_up.jsp'>注册</a>
        </h3>
        <form id="sign-in-form" class='form-horizontal' action='user' method='post'>
            <input type='hidden' name='action' value='signIn'>
            <div class='input-group'>
                <span class='input-group-addon'><i class='glyphicon glyphicon-phone'></i></span>
                <input id="mobile" name='mobile' class='form-control input-lg' type='text' placeholder='手机号或邮箱'
                       value="18612345678">
            </div>
            <small id='mobile-message'></small>
            <div class='input-group'>
                <span class='input-group-addon'><i class='glyphicon glyphicon-lock'></i></span>
                <input id="password" name='password' class='form-control input-lg' type='password' placeholder='密码'
                       value="123">
            </div>
            <small id='password-message'></small>
            <div class="input-group">
                <img id="kaptchaImg" src="kaptcha.jpg" alt="">
            </div>
            <div class='input-group'>
                <span class='input-group-addon'><i class='glyphicon glyphicon-check'></i></span>
                <input id="kaptcha" name='kaptchaReceived' class='form-control input-lg' type='text' placeholder='验证码'
                       value="123">
            </div>
            <small id='password-kaptcha'></small>
            <div class="checkbox">
                <label class="text-muted"><input type="checkbox" checked="checked"> 记住我</label>
                <a class="pull-right text-muted" href="">登录遇到问题？</a>
            </div>
            <button class='btn btn-primary btn-lg btn-block'>登录</button>
        </form>
        <small class="text-danger">${requestScope.message}</small>
    </div>
</div>
</body>
</html>
