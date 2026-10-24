from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CourseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    description: str = Field(default="", max_length=10000)


class CourseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=180)
    description: str | None = Field(default=None, max_length=10000)


class CourseOut(BaseModel):
    id: int
    title: str
    description: str
    creator_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class LessonCreate(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    content: str = Field(default="", max_length=50000)
    position: int = Field(default=1, ge=1)


class LessonOut(BaseModel):
    id: int
    course_id: int
    title: str
    content: str
    position: int
    model_config = ConfigDict(from_attributes=True)


class ProgressUpdate(BaseModel):
    completed: bool
