import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI()

# CORS erlauben, damit dein HTML/JS im Browser zugreifen darf
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # für Entwicklung ok
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def get_root():
    return FileResponse("index.html")

@app.get("/translations")
def get_translations():
    with open("translations.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data 
