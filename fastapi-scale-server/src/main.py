from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from api.endpoints import router as api_router

app = FastAPI(
    title="FastAPI SCALE Server",
    description="A FastAPI server for handling SCALE codec serialization.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/")
async def root():
    return {"message": "Welcome to the FastAPI SCALE Server!"}

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred."}
    )