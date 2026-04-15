import sqlalchemy
import pandas as pd
import sqlite3
import os

# class Database:
#     def __init__(self, db_name):
#         self.db_name = db_name
#         self.engine = sqlalchemy.create_engine(f'sqlite:///{db_name}')
#         self.conn = sqlite3.connect(db_name)
#         self.cursor = self.conn.cursor()
        
#     def create_table(self, table_name, columns):
 
 
from fastapi import FastAPI, UploadFile, File

import io

app = FastAPI()

@app.post("/upload-csv")
async def handle_upload(file: UploadFile = File(...)):
    # 1. Read the content of the uploaded file
    content = await file.read()
    
    # 2. Use BytesIO to make the content readable by Pandas
    df = pd.read_csv(io.BytesIO(content))
    
    # 3. Do something with the data
    data_summary = df.head().to_dict()
    
    return {
        "filename": file.filename,
        "rows": len(df),
        "preview": data_summary
    }       