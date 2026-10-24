import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from pwdlib import PasswordHash
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg://postgres:your_password@localhost:5432/learning_db"
    )
    jwt_secret_key: str = "replace-this-with-a-long-random-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
    )
    full_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(
        String(20),
        default="user",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    courses: Mapped[list["Course"]] = relationship(
        back_populates="creator",
    )


class Course(Base):
    __tablename__ = "courses"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(
        String(180),
        index=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    creator_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    creator: Mapped["User"] = relationship(
        back_populates="courses",
    )
    lessons: Mapped[list["Lesson"]] = relationship(
        back_populates="course",
        cascade="all, delete-orphan",
    )
    enrollments: Mapped[list["Enrollment"]] = relationship(
        back_populates="course",
        cascade="all, delete-orphan",
    )


class Lesson(Base):
    __tablename__ = "lessons"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    course_id: Mapped[int] = mapped_column(
        ForeignKey("courses.id", ondelete="CASCADE"),
        index=True,
    )
    title: Mapped[str] = mapped_column(String(180))
    content: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    position: Mapped[int] = mapped_column(
        Integer,
        default=1,
    )

    course: Mapped["Course"] = relationship(
        back_populates="lessons",
    )
    progress_records: Mapped[list["LessonProgress"]] = relationship(
        back_populates="lesson",
        cascade="all, delete-orphan",
    )


class Enrollment(Base):
    __tablename__ = "enrollments"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "course_id",
            name="uq_enrollment_user_course",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    course_id: Mapped[int] = mapped_column(
        ForeignKey("courses.id", ondelete="CASCADE"),
        index=True,
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    course: Mapped["Course"] = relationship(
        back_populates="enrollments",
    )


class LessonProgress(Base):
    __tablename__ = "lesson_progress"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "lesson_id",
            name="uq_progress_user_lesson",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    lesson_id: Mapped[int] = mapped_column(
        ForeignKey("lessons.id", ondelete="CASCADE"),
        index=True,
    )
    completed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    lesson: Mapped["Lesson"] = relationship(
        back_populates="progress_records",
    )


class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(
        min_length=1,
        max_length=120,
    )
    password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("full_name")
    @classmethod
    def strip_full_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Full name cannot be blank")
        return value


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=128,
    )


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
    title: str = Field(
        min_length=1,
        max_length=180,
    )
    description: str = Field(
        default="",
        max_length=10000,
    )


class CourseUpdate(BaseModel):
    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=180,
    )
    description: str | None = Field(
        default=None,
        max_length=10000,
    )


class CourseOut(BaseModel):
    id: int
    title: str
    description: str
    creator_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LessonCreate(BaseModel):
    title: str = Field(
        min_length=1,
        max_length=180,
    )
    content: str = Field(
        default="",
        max_length=50000,
    )
    position: int = Field(
        default=1,
        ge=1,
    )


class LessonOut(BaseModel):
    id: int
    course_id: int
    title: str
    content: str
    position: int

    model_config = ConfigDict(from_attributes=True)


class ProgressUpdate(BaseModel):
    completed: bool


class ProgressOut(BaseModel):
    lesson_id: int
    course_id: int
    lesson_title: str
    completed: bool
    completed_at: datetime | None


password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_hash.verify(password, hashed)


def create_access_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload = {
        "sub": str(user_id),
        "exp": expires,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = int(payload.get("sub", ""))

    except (InvalidTokenError, ValueError, TypeError):
        raise unauthorized

    user = db.get(User, user_id)

    if user is None:
        raise unauthorized

    return user


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Learning Platform API",
    description=(
        "Backend portfolio: authentication, course management, "
        "and learning progress."
    ),
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Learning Platform API is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post(
    "/auth/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
)
def register(
    data: RegisterIn,
    db: Session = Depends(get_db),
):
    email = str(data.email).lower()

    existing = db.scalar(
        select(User).where(User.email == email)
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        )

    user = User(
        email=email,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        )

    return user


@app.post("/auth/login", response_model=TokenOut)
def login(
    data: LoginIn,
    db: Session = Depends(get_db),
):
    user = db.scalar(
        select(User).where(
            User.email == str(data.email).lower()
        )
    )

    if user is None or not verify_password(
        data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    return TokenOut(
        access_token=create_access_token(user.id)
    )


@app.get("/auth/me", response_model=UserOut)
def me(
    current_user: User = Depends(get_current_user),
):
    return current_user


@app.get("/courses", response_model=list[CourseOut])
def list_courses(
    db: Session = Depends(get_db),
):
    return list(
        db.scalars(
            select(Course).order_by(Course.id.desc())
        ).all()
    )


@app.post(
    "/courses",
    response_model=CourseOut,
    status_code=status.HTTP_201_CREATED,
)
def create_course(
    data: CourseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = Course(
        title=data.title,
        description=data.description,
        creator_id=current_user.id,
    )

    db.add(course)
    db.commit()
    db.refresh(course)

    return course


@app.get("/courses/{course_id}", response_model=CourseOut)
def get_course(
    course_id: int,
    db: Session = Depends(get_db),
):
    course = db.get(Course, course_id)

    if course is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found",
        )

    return course


def ensure_course_owner(
    course: Course,
    user: User,
):
    if course.creator_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the course creator or an admin can perform this action",
        )


@app.patch(
    "/courses/{course_id}",
    response_model=CourseOut,
)
def update_course(
    course_id: int,
    data: CourseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(Course, course_id)

    if course is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found",
        )

    ensure_course_owner(course, current_user)

    for key, value in data.model_dump(
        exclude_unset=True
    ).items():
        if value is not None:
            setattr(course, key, value)

    db.commit()
    db.refresh(course)

    return course


@app.post(
    "/courses/{course_id}/enroll",
    status_code=status.HTTP_201_CREATED,
)
def enroll_course(
    course_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(Course, course_id)

    if course is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found",
        )

    existing = db.scalar(
        select(Enrollment).where(
            Enrollment.user_id == current_user.id,
            Enrollment.course_id == course_id,
        )
    )

    if existing:
        return {
            "message": "You are already enrolled in this course"
        }

    enrollment = Enrollment(
        user_id=current_user.id,
        course_id=course_id,
    )

    db.add(enrollment)
    db.commit()

    return {
        "message": "Successfully enrolled in the course",
        "course_id": course_id,
    }


@app.post(
    "/courses/{course_id}/lessons",
    response_model=LessonOut,
    status_code=status.HTTP_201_CREATED,
)
def create_lesson(
    course_id: int,
    data: LessonCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(Course, course_id)

    if course is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found",
        )

    ensure_course_owner(course, current_user)

    lesson = Lesson(
        course_id=course_id,
        title=data.title,
        content=data.content,
        position=data.position,
    )

    db.add(lesson)
    db.commit()
    db.refresh(lesson)

    return lesson


@app.get(
    "/courses/{course_id}/lessons",
    response_model=list[LessonOut],
)
def list_lessons(
    course_id: int,
    db: Session = Depends(get_db),
):
    course = db.get(Course, course_id)

    if course is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found",
        )

    return list(
        db.scalars(
            select(Lesson)
            .where(Lesson.course_id == course_id)
            .order_by(Lesson.position)
        ).all()
    )


@app.put(
    "/lessons/{lesson_id}/progress",
    response_model=ProgressOut,
)
def update_progress(
    lesson_id: int,
    data: ProgressUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    lesson = db.get(Lesson, lesson_id)

    if lesson is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lesson not found",
        )

    enrollment = db.scalar(
        select(Enrollment).where(
            Enrollment.user_id == current_user.id,
            Enrollment.course_id == lesson.course_id,
        )
    )

    if enrollment is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please enroll in the course first",
        )

    progress = db.scalar(
        select(LessonProgress).where(
            LessonProgress.user_id == current_user.id,
            LessonProgress.lesson_id == lesson_id,
        )
    )

    if progress is None:
        progress = LessonProgress(
            user_id=current_user.id,
            lesson_id=lesson_id,
        )
        db.add(progress)

    progress.completed = data.completed

    progress.completed_at = (
        datetime.now(timezone.utc)
        if data.completed
        else None
    )

    db.commit()
    db.refresh(progress)

    return ProgressOut(
        lesson_id=lesson.id,
        course_id=lesson.course_id,
        lesson_title=lesson.title,
        completed=progress.completed,
        completed_at=progress.completed_at,
    )


@app.get("/progress/me")
def my_progress(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enrollments = list(
        db.scalars(
            select(Enrollment).where(
                Enrollment.user_id == current_user.id
            )
        ).all()
    )

    result = []

    for enrollment in enrollments:
        course = db.get(Course, enrollment.course_id)

        if course is None:
            continue

        lessons = list(
            db.scalars(
                select(Lesson).where(
                    Lesson.course_id == enrollment.course_id
                )
            ).all()
        )

        completed_count = 0

        for lesson in lessons:
            progress = db.scalar(
                select(LessonProgress).where(
                    LessonProgress.user_id == current_user.id,
                    LessonProgress.lesson_id == lesson.id,
                )
            )

            if progress and progress.completed:
                completed_count += 1

        total = len(lessons)

        result.append(
            {
                "course_id": course.id,
                "course_title": course.title,
                "total_lessons": total,
                "completed_lessons": completed_count,
                "progress_percent": (
                    round(completed_count / total * 100, 2)
                    if total
                    else 0
                ),
            }
        )

    return result
