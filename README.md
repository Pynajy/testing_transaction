### Пути
- **/admin** - Админ панель
- **/admin/users** - Пользователи
- **/admin/transactions** - Транзакции
- **/apidocs/** - Swagger

### Команды
- **flask run** - Запуск
- **flask create-admin 100.0** - Создать админа с балансом 100 

**Запуск Celery windows**
- **celery -A app.celery worker --loglevel=info --pool=solo**
- **celery -A app.celery beat --loglevel=info**

