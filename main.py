from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.dependencies import get_current_user
from app.models import Course, Enrollment, Lesson, LessonProgress, User
from app.schemas import (
    RegisterIn, LoginIn, UserOut, TokenOut, CourseCreate, CourseUpdate, CourseOut,
    LessonCreate, LessonOut, ProgressUpdate,
)
from app.security import create_access_token, hash_password, verify_password


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Learning Platform API",
    description="Backend portfolio: authentication, course management, and learning progress.",
    version="1.0.0",
)


@app.get("/")
def root():
    return {"message": "Learning Platform API is running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == data.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="Email is already registered")
    user = User(
        email=data.email.lower(),
        full_name=data.full_name.strip(),
        password_hash=hash_password(data.password),
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email is already registered")
    return user


@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return TokenOut(access_token=create_access_token(user.id))


@app.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/courses", response_model=list[CourseOut])
def list_courses(db: Session = Depends(get_db)):
    return list(db.scalars(select(Course).order_by(Course.id.desc())).all())


@app.post("/courses", response_model=CourseOut, status_code=201)
def create_course(
    data: CourseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = Course(title=data.title, description=data.description, creator_id=current_user.id)
    db.add(course)
    db.commit()
    db.refresh(course)
    return course


@app.get("/courses/{course_id}", response_model=CourseOut)
def get_course(course_id: int, db: Session = Depends(get_db)):
    course = db.get(Course, course_id)
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    return course


def ensure_course_owner(course: Course, user: User):
    if course.creator_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the course creator or an admin can perform this action")


@app.patch("/courses/{course_id}", response_model=CourseOut)
def update_course(
    course_id: int,
    data: CourseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(Course, course_id)
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    ensure_course_owner(course, current_user)
    for key, value in data.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(course, key, value)
    db.commit()
    db.refresh(course)
    return course


@app.post("/courses/{course_id}/enroll", status_code=201)
def enroll_course(
    course_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if db.get(Course, course_id) is None:
        raise HTTPException(status_code=404, detail="Course not found")
    existing = db.scalar(select(Enrollment).where(
        Enrollment.user_id == current_user.id,
        Enrollment.course_id == course_id,
    ))
    if existing:
        return {"message": "You are already enrolled in this course"}
    db.add(Enrollment(user_id=current_user.id, course_id=course_id))
    db.commit()
    return {"message": "Successfully enrolled in course", "course_id": course_id}


@app.post("/courses/{course_id}/lessons", response_model=LessonOut, status_code=201)
def create_lesson(
    course_id: int,
    data: LessonCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(Course, course_id)
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    ensure_course_owner(course, current_user)
    lesson = Lesson(course_id=course_id, title=data.title, content=data.content, position=data.position)
    db.add(lesson)
    db.commit()
    db.refresh(lesson)
    return lesson


@app.get("/courses/{course_id}/lessons", response_model=list[LessonOut])
def list_lessons(course_id: int, db: Session = Depends(get_db)):
    if db.get(Course, course_id) is None:
        raise HTTPException(status_code=404, detail="Course not found")
    return list(db.scalars(
        select(Lesson).where(Lesson.course_id == course_id).order_by(Lesson.position)
    ).all())


@app.put("/lessons/{lesson_id}/progress")
def update_progress(
    lesson_id: int,
    data: ProgressUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    lesson = db.get(Lesson, lesson_id)
    if lesson is None:
        raise HTTPException(status_code=404, detail="Lesson not found")
    enrollment = db.scalar(select(Enrollment).where(
        Enrollment.user_id == current_user.id,
        Enrollment.course_id == lesson.course_id,
    ))
    if enrollment is None:
        raise HTTPException(status_code=403, detail="Enroll in the course first")
    progress = db.scalar(select(LessonProgress).where(
        LessonProgress.user_id == current_user.id,
        LessonProgress.lesson_id == lesson_id,
    ))
    if progress is None:
        progress = LessonProgress(user_id=current_user.id, lesson_id=lesson_id)
        db.add(progress)
    progress.completed = data.completed
    progress.completed_at = datetime.now(timezone.utc) if data.completed else None
    db.commit()
    return {
        "lesson_id": lesson.id,
        "course_id": lesson.course_id,
        "lesson_title": lesson.title,
        "completed": progress.completed,
        "completed_at": progress.completed_at,
    }


@app.get("/progress/me")
def my_progress(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enrollments = list(db.scalars(
        select(Enrollment).where(Enrollment.user_id == current_user.id)
    ).all())
    result = []
    for enrollment in enrollments:
        course = db.get(Course, enrollment.course_id)
        lessons = list(db.scalars(
            select(Lesson).where(Lesson.course_id == enrollment.course_id)
        ).all())
        completed_count = 0
        for lesson in lessons:
            progress = db.scalar(select(LessonProgress).where(
                LessonProgress.user_id == current_user.id,
                LessonProgress.lesson_id == lesson.id,
            ))
            if progress and progress.completed:
                completed_count += 1
        total = len(lessons)
        result.append({
            "course_id": course.id,
            "course_title": course.title,
            "total_lessons": total,
            "completed_lessons": completed_count,
            "progress_percent": round(completed_count / total * 100, 2) if total else 0,
        })
    return result
