from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response
import os
from gmssl import sm4


def xor(byte1, byte2):
    result = bytes(x ^ y for x, y in zip(byte1, byte2))
    return result


key = os.urandom(16)
iv = os.urandom(16)
sm4_encryption = sm4.CryptSM4()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = b'palupalupalupalupalupalupalupalupalu' 
# 保留原始的用户数据访问对象 (DAO)
class UserDAO(object):
    def __init__(self):
        self.users: dict[str, str] = {}

    def getPassword(self, uid: str) -> str:
        if uid not in self.users:
            raise Exception('用户不存在')
        return self.users[uid]

    def create(self, uid: str, password: str):
        if uid in self.users:
            raise Exception('用户已注册')
        self.users[uid] = password
        return

DAO = UserDAO()
DAO.create('demoUser', '123456')

# --- Flask 路由 --- 

@app.route('/')
def index():
    if 'uid' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uid = request.form.get('uid')
        if 'admin' in uid:
            flash('不可以是admin哦', 'error')
            return redirect(url_for('register'))
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not uid or not password:
            flash('用户ID和密码不可为空', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return redirect(url_for('register'))

        try:
            DAO.create(uid, password)
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(str(e.args[0]), 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')

        if not uid or not password:
            flash('用户ID和密码不可为空', 'error')
            return redirect(url_for('login'))

        try:
            stored_password = DAO.getPassword(uid)
            if stored_password != password:
                raise Exception('用户ID或密码错误')

            user_level = 'admin' if uid == 'admin' else 'guest'
            
            sm4_encryption.set_key(key, sm4.SM4_ENCRYPT)
            token_payload = f"{uid}:{user_level}".encode('utf-8')
            token = sm4_encryption.crypt_cbc(iv, token_payload).hex()

            session['uid'] = uid
            flash(f'登录成功，您的 token 是: {token}', 'success')
            # 创建响应对象并设置 cookie
            response = make_response(redirect(url_for('profile')))
            response.set_cookie('auth_token', token, httponly=True, samesite='Lax') # 设置 cookie
            return response

        except Exception as e:
            flash(str(e.args[0]), 'error') # 显示更具体的错误信息
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    # 可以在这里添加解密 token 显示信息的逻辑，但暂时只显示用户名
    username = session.get('uid')
    return render_template('profile.html', username=username)

@app.route('/logout')
def logout():
    session.pop('uid', None)
    flash('您已成功登出', 'info')
    return redirect(url_for('login'))

@app.route('/file', methods=['GET', 'POST'])
def read_file_page():
    if 'uid' not in session :
        flash('请先登录', 'warning')
        return redirect(url_for('login'))
    print(session)
    
    file_content = None
    error_message = None
    file_path_requested = ''

    if request.method == 'POST':
        token = request.cookies.get('auth_token') # 从 cookie 获取 token
        file_path = request.form.get('path')
        file_path_requested = file_path # 保留用户输入的路径以便回显
        if not file_path:
            error_message = '路径不可为空'
        else:
            try:
                # 保留原始的 SM4 CBC 令牌验证逻辑
                sm4_encryption.set_key(key, sm4.SM4_DECRYPT)
                token_decrypted = sm4_encryption.crypt_cbc(iv, bytes.fromhex(token))
                decrypted_str = token_decrypted.decode('utf-8', errors='ignore') 
                parts = decrypted_str.split(':')[-2:]

                uid_from_token, lv = parts

                if 'admin' in lv:
                    print(f"管理员 {uid_from_token} 尝试读取: {file_path}")
                    try:

                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_content = f.read()
                    except FileNotFoundError:
                        error_message = '文件未找到'
                    except Exception as e:
                        print(f"读取文件错误: {e}")
                        error_message = '读取文件失败'
                else:
                    error_message = '非管理员，无权限读取服务器文件'
            except ValueError as e:
                 error_message = f'token非法: {e}'
            except Exception as e:
                print(f"Token 解密/验证错误: {e}")
                error_message = 'token无效或已过期'

    if error_message:
        flash(error_message, 'error')
        
    return render_template('file_viewer.html', file_content=file_content, file_path_requested=file_path_requested)

# 移除 Flask-RESTX 的 404 处理，使用 Flask 默认或自定义模板
@app.errorhandler(404)
def page_not_found(e):
    # 可以创建一个 templates/404.html 页面
    return render_template('404.html'), 404 

if __name__ == '__main__':
    # 确保 static 文件夹存在
    if not os.path.exists('static'):
        os.makedirs('static')
    # 确保 templates 文件夹存在
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # 404 页面
    if not os.path.exists('templates/404.html'):
        with open('templates/404.html', 'w', encoding='utf-8') as f:
            f.write('<!doctype html><title>404 Not Found</title><h1>页面未找到</h1><p>您访问的页面不存在。</p><a href="/">返回首页</a>')

    if not os.path.exists('static/style.css'):
         with open('static/style.css', 'w', encoding='utf-8') as f:
            f.write('''
body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; }
.container { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
h1 { color: #333; }
.form-group { margin-bottom: 15px; }
label { display: block; margin-bottom: 5px; }
input[type="text"], input[type="password"] { width: calc(100% - 22px); padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
button { background-color: #5cb85c; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
button:hover { background-color: #4cae4c; }
a { color: #0275d8; text-decoration: none; }
a:hover { text-decoration: underline; }
.flash-messages { margin-bottom: 15px; }
.alert { padding: 10px; border-radius: 4px; margin-bottom: 10px; }
.alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
.alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
.alert-info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
.alert-warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
.file-content { margin-top: 20px; padding: 15px; background-color: #eee; border: 1px solid #ddd; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
nav { margin-bottom: 20px; text-align: right; }
nav span { margin-right: 15px; }
            ''')

    app.run(debug=True, host='0.0.0.0', port=10002)