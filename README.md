### Пути
- **/admin** - Админ панель
- **/admin/users** - Пользователи
- **/admin/transactions** - Транзакции
- **/login** - Авторизация
- **/logout** - Выход из аккаунта
- **/apidocs/** - Swagger
- **/admin/user/"user_id"/token/** - Токены приложений пользователя

### Команды
- **flask run** - Запуск
- **flask create-admin "username" "password"** - Создать админа 

**Запуск Celery windows**
- **celery -A app.celery worker --loglevel=info --pool=solo**
- **celery -A app.celery beat --loglevel=info**

**Admin**
- **admin** - Логин
- **123** - Пароль