from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///crypto.db")
Base = declarative_base()
Session = sessionmaker(bind=engine)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    coin = Column(String)
    threshold = Column(Float)

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    coin = Column(String)
    price = Column(Float)
    timestamp = Column(DateTime, default=func.now())

Base.metadata.create_all(engine)
