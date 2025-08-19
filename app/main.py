from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, password_reset, dashboard 

app = FastAPI()

# ✅ Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:3001" , "*"], # or ["*"] during dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Pet Ecom API is running"}

# ✅ Include routers
app.include_router(auth.router)
app.include_router(password_reset.router)
app.include_router(dashboard.router)        