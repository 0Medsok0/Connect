from flask import Flask, render_template, redirect, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_avatars import Avatars
import os
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired
from flask_login import login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_network.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['AVATARS_DEFAULT_SIZE'] = (200, 200)
app.config['AVATARS_DEFAULT_URL'] = 'https://www.gravatar.com/avatar/?d=identicon'
app.config['AVATARS_DEFAULT_EXTENSION'] = 'png'
app.config['AVATARS_UPLOAD_PATH'] = 'static/uploads/'
app.config['AVATARS_ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

avatars = Avatars(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

friendships = db.Table('friendships',
                       db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                       db.Column('friend_id', db.Integer, db.ForeignKey('user.id'))
                       )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    friends = db.relationship('User', secondary=friendships,
                              primaryjoin=(friendships.c.user_id == id),
                              secondaryjoin=(friendships.c.friend_id == id),
                              backref=db.backref('friends_of', lazy='dynamic'),
                              lazy='dynamic')
    avatar = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(50), nullable=True)
    age = db.Column(db.String(10), nullable=True)
    city = db.Column(db.String(50), nullable=True)
    life_position = db.Column(db.Text, nullable=True)
    interests = db.Column(db.Text, nullable=True)


class AboutMeForm(FlaskForm):
    country = SelectField('Country', choices=[('Afghanistan', 'Russia', 'USA', 'Australia', 'Africa'), ...], validators=[DataRequired()])
    age = SelectField('Age', choices=[('13-18', '19-25', '25-31', '31-45', '45-55', '55-100'), ...], validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    life_position = TextAreaField('Life Position', validators=[DataRequired()])
    interests = TextAreaField('Interests', validators=[DataRequired()])
    submit = SubmitField('Save')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy=True))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=True)
    comments = db.relationship('Comment', backref='post', lazy=True)
    likes = db.relationship('Like', backref='post', lazy=True)


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('comments', lazy=True))


class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    posts = db.relationship('Post', backref='community', lazy=True)


class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_friend_requests', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id],
                                backref=db.backref('received_friend_requests', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Регистрация

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/avatar/<path:filename>')
def avatar(filename):
    return send_from_directory(app.config['AVATARS_UPLOAD_PATH'], filename)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        avatar = request.files['avatar']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if avatar and allowed_file(avatar.filename):
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['AVATARS_UPLOAD_PATH'], filename))
            avatar_url = url_for('avatar', filename=filename)
        else:
            avatar_url = None

        new_user = User(username=username, password_hash=hashed_password, email=email, avatar=avatar_url)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


# Обо мне
@app.route('/about_me', methods=['GET', 'POST'])
@login_required
def about_me():
    form = AboutMeForm()
    if form.validate_on_submit():
        current_user.country = form.country.data
        current_user.age = form.age.data
        current_user.city = form.city.data
        current_user.life_position = form.life_position.data
        current_user.interests = form.interests.data
        db.session.commit()
    return render_template('about_me_form.html', form=form)


# Обновить инофрмацию обо мне
@app.route('/update_about_me', methods=['POST'])
@login_required
def update_about_me():
    if request.method == 'POST':
        current_user.country = request.form['country']
        current_user.age = request.form['age']
        current_user.city = request.form['city']
        current_user.life_position = request.form['life_position']
        current_user.interests = request.form['interests']
        db.session.commit()
        return redirect(url_for('about_me'))
    return render_template('about_me_form.html', form=AboutMeForm())


# Логин
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')


# Выйти
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Домашняя страница
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        content = request.form['content']
        new_post = Post(content=content, author=current_user)
        db.session.add(new_post)
        db.session.commit()
    posts = Post.query.filter_by(author=current_user).order_by(Post.id.desc()).all()
    user_info = {
        'country': current_user.country,
        'age': current_user.age,
        'city': current_user.city,
        'life_position': current_user.life_position,
        'interests': current_user.interests,
    }
    return render_template('home.html', posts=posts, user=User, user_info=user_info)


# Коментарии
@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    post = Post.query.get_or_404(post_id)
    new_comment = Comment(content=content, author=current_user, post=post)
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for('home'))


# Лайки
@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.likes or all(like.user_id != current_user.id for like in post.likes):
        like = Like(user=current_user, post=post)
        db.session.add(like)
        db.session.commit()
    return str(len(post.likes))


# Добавить в друзья
@app.route('/add_friends', methods=['GET', 'POST'])
@login_required
def add_friends():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get_or_404(user_id)
        if user not in current_user.friends:
            friend_request = FriendRequest(sender=current_user, recipient=user)
            db.session.add(friend_request)
            db.session.commit()
        return redirect(url_for('home'))
    else:
        users = User.query.filter(User.id != current_user.id).all()
        return render_template('add_friends.html', users=users)


# Посмотреть список друзей
@app.route('/friends')
@login_required
def friends():
    friends = current_user.friends.all()
    return render_template('friends.html', friends=friends)


# маршрут для отображения запросов на дружбу
@app.route('/friend_requests')
@login_required
def friend_requests():
    friend_requests = FriendRequest.query.filter_by(recipient=current_user).all()
    return render_template('friend_requests.html', friend_requests=friend_requests)


# маршрут для принятия или отклонения запроса на дружбу
@app.route('/friend_requests/<int:request_id>/<action>')
@login_required
def handle_friend_request(request_id, action):
    friend_request = FriendRequest.query.get_or_404(request_id)
    if friend_request.recipient != current_user:
        abort(403)
    if action == 'accept':
        current_user.friends.append(friend_request.sender)
        friend_request.sender.friends.append(current_user)
    db.session.delete(friend_request)
    db.session.commit()
    return redirect(url_for('friend_requests'))


# Сообщения
@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        recipient_id = request.form['recipient']
        recipient = User.query.get_or_404(recipient_id)
        content = request.form['content']
        new_message = Message(content=content, sender=current_user, recipient=recipient)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('home'))
    else:
        friends = current_user.friends.all()
        return render_template('send_message.html', friends=friends)


# маршрут для отображения полученных сообщений
@app.route('/inbox')
@login_required
def inbox():
    messages = Message.query.filter_by(recipient=current_user).all()
    return render_template('inbox.html', messages=messages)


# Создать сообщество
@app.route('/create_community', methods=['GET', 'POST'])
@login_required
def create_community():
    if request.method == 'POST':
        name = request.form['name']
        new_community = Community(name=name)  # creator=current_user
        db.session.add(new_community)
        db.session.commit()
        return redirect(url_for('community_page', community_id=new_community.id))
    return render_template('create_community.html')


# Сообщества посмотреть
@app.route('/community/<int:community_id>')
@login_required
def community_page(community_id):
    community = Community.query.get_or_404(community_id)
    posts = Post.query.filter_by(community=community).order_by(Post.id.desc()).all()
    return render_template('community.html', community=community, posts=posts)


# Перейти в профиль друга(Посомтреь его посты)(Есть возможность оставить коментарий и поставить лайк)
@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(author=user).options(db.joinedload(Post.likes)).order_by(Post.id.desc()).all()
    return render_template('user_profile.html', user=user, posts=posts)

# Аватар
@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'file' not in request.files:
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['AVATARS_UPLOAD_PATH'], filename))
        current_user.avatar = filename
        db.session.commit()
        uploaded_successfully = True
    else:
        uploaded_successfully = False

    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
