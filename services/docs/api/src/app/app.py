from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

# from app.db import init_db
from app.api import api
from app.db import init_db
from .config import settings

app = FastAPI()



@app.on_event("startup")
async def start_db():
    await init_db(settings.mongo_uri)


@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"error": str(exc)},
    )


app.include_router(api, prefix="/api")