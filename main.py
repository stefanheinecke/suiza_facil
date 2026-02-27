from fastapi import FastAPI


app = FastAPI()

@app.get("/text")
def get_text():
    return "Test-Text"