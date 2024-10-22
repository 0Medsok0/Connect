# Connect

<div>
    <img src="picture/connect.png" alt="">
</div>

Connect - Социальная сеть поддерживает основные функции, такие как регистрация и вход пользователей, создание постов,
комментариев и лайков, добавление друзей и отправка сообщений.

Код представляет собой базовую структуру социальной сети, созданной с использованием Flask, SQLAlchemy и Flask-Login.
описание основных функций и моделей, которые были реализованны в коде:
# Модели данных
User: Представляет пользователя социальной сети. Имеет поля для хранения имени пользователя и хэшированного пароля. Также имеет связи с постами, комментариями и сообщениями.
Message: Представляет сообщение, отправленное от одного пользователя другому. Имеет поля для хранения содержимого сообщения, идентификаторов отправителя и получателя.
Post: Представляет пост, опубликованный пользователем. Имеет поле для хранения содержимого поста и связь с комментариями.
Comment: Представляет комментарий, оставленный пользователем к посту. Имеет поле для хранения содержимого комментария.
Community: Представляет сообщество, созданное пользователями. Имеет поле для хранения названия сообщества и связь с постами.

# Аутентификация и авторизация
register: Маршрут для регистрации новых пользователей. Принимает имя пользователя и пароль, хэширует пароль и сохраняет нового пользователя в базе данных.
login: Маршрут для входа существующих пользователей. Проверяет имя пользователя и пароль, аутентифицирует пользователя и устанавливает сеанс.
logout: Маршрут для выхода из сеанса текущего пользователя.

# Функциональность
home: Маршрут для главной страницы пользователя, на которой отображаются все посты. Пользователь может создавать новые посты.
add_comment: Маршрут для добавления комментария к посту.
like_post: Маршрут для лайка поста.
add_friend: Маршрут для добавления друга.
send_message: Маршрут для отправки сообщения другому пользователю.
community_page: Маршрут для просмотра страницы сообщества.

register.html: Шаблон для страницы регистрации.
login.html: Шаблон для страницы входа.
home.html: Шаблон для главной страницы пользователя.
user_profile.html: Шаблон для страницы профиля пользователя.
send_message.html: Шаблон для страницы отправки сообщения.
community.html: Шаблон для страницы сообщества.
news.html: Шаблон для страницы новостей.
