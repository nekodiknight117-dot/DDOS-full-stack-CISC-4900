from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )

    logs: Mapped[list["Log"]] = relationship("Log", back_populates="user")


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="logs")
    log_data: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )

    analyses: Mapped[list["Analysis"]] = relationship(
        "Analysis", back_populates="log"
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), nullable=False)
    log: Mapped["Log"] = relationship("Log", back_populates="analyses")
    analysis_data: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )

    analysis_results: Mapped[list["AnalysisResult"]] = relationship(
        "AnalysisResult", back_populates="analysis"
    )
    csv_sample_rows: Mapped[list["CsvSampleRow"]] = relationship(
        "CsvSampleRow",
        back_populates="analysis",
        order_by="CsvSampleRow.row_index",
    )


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id"), nullable=False
    )
    analysis: Mapped["Analysis"] = relationship(
        "Analysis", back_populates="analysis_results"
    )
    malware_location: Mapped[str] = mapped_column("malwareLocation", Text, nullable=False)
    malware_quantity: Mapped[int] = mapped_column("malwareQuantiy", Integer, nullable=False)
    analysis_classification: Mapped[bool] = mapped_column(
        "analysisclassification", Boolean, nullable=False
    )


class CsvSampleRow(Base):
    __tablename__ = "csv_sample_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id"), nullable=False, index=True
    )
    analysis: Mapped["Analysis"] = relationship(
        "Analysis", back_populates="csv_sample_rows"
    )
    row_index: Mapped[int] = mapped_column(Integer, nullable=False)
    row_data: Mapped[str] = mapped_column(Text, nullable=False)
    full_csv: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
