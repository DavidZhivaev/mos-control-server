from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

app = FastAPI()

# ПОКА ЧТО СКУЛАЙТ, ПТТОМ КОГДА НА СЕРВАК ЗАКИНЕМ ПОМЕНЯЮ НА ПСКЛЬ!!!
register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["models.user", "models.session"]},
    generate_schemas=True,
    add_exception_handlers=True,
)