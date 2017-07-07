package jianshu.datalab.xin.model;

import java.io.Serializable;


public class User implements Serializable { // 标识接口

    private Integer id;
    private String nick;
    private String mobile;
    private String password;
    private String avatar;
    private int    pay;
    private double money;
    private String lastIp;
    private String lastTime;
    private String signUpTime;

    public User() {
    }

    public User(String nick, String mobile, String password, String lastIp) {
        this.nick = nick;
        this.mobile = mobile;
        this.password = password;
        this.lastIp = lastIp;
    }

    public User(Integer id, String nick, String mobile, String password, String avatar, int pay, double money, String lastIp, String lastTime, String signUpTime) {

        this.id = id;
        this.nick = nick;
        this.mobile = mobile;
        this.password = password;
        this.avatar = avatar;
        this.pay = pay;
        this.money = money;
        this.lastIp = lastIp;
        this.lastTime = lastTime;
        this.signUpTime = signUpTime;
    }

    public Integer getId() {

        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getNick() {
        return nick;
    }

    public void setNick(String nick) {
        this.nick = nick;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public int getPay() {
        return pay;
    }

    public void setPay(int pay) {
        this.pay = pay;
    }

    public double getMoney() {
        return money;
    }

    public void setMoney(double money) {
        this.money = money;
    }

    public String getLastIp() {
        return lastIp;
    }

    public void setLastIp(String lastIp) {
        this.lastIp = lastIp;
    }

    public String getLastTime() {
        return lastTime;
    }

    public void setLastTime(String lastTime) {
        this.lastTime = lastTime;
    }

    public String getSignUpTime() {
        return signUpTime;
    }

    public void setSignUpTime(String signUpTime) {
        this.signUpTime = signUpTime;
    }
}
