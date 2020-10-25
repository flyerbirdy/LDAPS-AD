from flask import Flask, render_template, redirect, request, flash, url_for, session
from flask_wtf.csrf import CSRFProtect
import ldap

##Ldap binding

dn = "CN=Administrator,CN=Users,DC=Home,DC=com"  ##Needs AccountOperation
pw = "123.com"
cert_file='/home/flask/cert/ca.crt'   ##CA。Sign to AD
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cert_file)
con = ldap.initialize('ldaps://Home-2016.Home.com')   ##Should using Domain not IP
con.simple_bind_s( dn, pw )

app = Flask(__name__)



@app.route('/')
def index():
    return render_template('base.html')  #Header Base

@app.route('/redirectFunc')
def redirectFunc():
    return redirect('tologinSonHtml')   

@app.route('/tologinSonHtml')
def tologinSonHtml():
    return render_template('login.html')



@app.route('/login', methods=['GET','POST'])
def login():
    userName = request.form['userName']
    Phone = request.form['Phone']
##Ldaqp
    base_dn = 'CN=Users,DC=Home,DC=com'
    filter = "(telephoneNumber={p})".format(p = Phone)
    attrs = ['sAMAccountName']


    
    adresult = con.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
    

    if adresult :
        adresult = str(adresult[0][1]['sAMAccountName'][0], encoding = "utf-8")
        distinguishedName = ['distinguishedName']
        distinguishedNameResult = con.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, distinguishedName)
        session['distinguishedNameResult'] = distinguishedNameResult[0][0]
    
    else :
        flash('找不到手机号') ##NoMobile
        return render_template('login.html')
        
    if userName == adresult and Phone == Phone:
        return render_template('renew.html', Name = adresult)
    else :
        flash('手机号和账号对不上[这边要做一个短信认证模块]') ##Mobile can't compare with Account
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/renew', methods=['GET','POST'])
def renew():

    username = session.get('distinguishedNameResult')
    password = request.form['password']
       

    newpwd_utf16 = '"{0}"'.format(password).encode('utf-16-le')
    mod_list = [(ldap.MOD_REPLACE, "unicodePwd", newpwd_utf16)]
    try:
        con.modify_s(username, mod_list)
        session.clear()
        return render_template('success.html')
    
    except:
        flash('密码不符合要求') ## Password not follow request
        return render_template('renew.html')


if __name__ == '__main__':
    app.secret_key = '123456'
    app.run(host='0.0.0.0', port=80, debug=True)