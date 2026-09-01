from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_delete, cache_get, cache_set
from app.db import get_session
from app.models import Task, TaskCreate, TaskUpdate
from app.orm_models import TaskORM
from app.security import get_current_user

router = APIRouter(prefix="/tasks", tags=["tasks"], dependencies=[Depends(get_current_user)])

TASKS_LIST_CACHE_KEY = "tasks:all"
_task_list_adapter = TypeAdapter(list[Task])


def _task_cache_key(task_id: int) -> str:
    return f"tasks:{task_id}"


@router.get("", response_model=list[Task])
async def list_tasks(session: AsyncSession = Depends(get_session)) -> list[Task]:
    cached = await cache_get(TASKS_LIST_CACHE_KEY)
    if cached is not None:
        return _task_list_adapter.validate_json(cached)

    result = await session.execute(select(TaskORM))
    tasks = [Task.model_validate(t) for t in result.scalars().all()]
    await cache_set(TASKS_LIST_CACHE_KEY, _task_list_adapter.dump_json(tasks).decode())
    return tasks


@router.get("/{task_id}", response_model=Task)
async def get_task(task_id: int, session: AsyncSession = Depends(get_session)) -> Task:
    cache_key = _task_cache_key(task_id)
    cached = await cache_get(cache_key)
    if cached is not None:
        return Task.model_validate_json(cached)

    task = await session.get(TaskORM, task_id)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    task_out = Task.model_validate(task)
    await cache_set(cache_key, task_out.model_dump_json())
    return task_out


@router.post("", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(payload: TaskCreate, session: AsyncSession = Depends(get_session)) -> Task:
    task = TaskORM(**payload.model_dump())
    session.add(task)
    await session.commit()
    await session.refresh(task)
    await cache_delete(TASKS_LIST_CACHE_KEY)
    return Task.model_validate(task)


@router.put("/{task_id}", response_model=Task)
async def update_task(
    task_id: int, payload: TaskUpdate, session: AsyncSession = Depends(get_session)
) -> Task:
    task = await session.get(TaskORM, task_id)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    await session.commit()
    await session.refresh(task)
    await cache_delete(TASKS_LIST_CACHE_KEY, _task_cache_key(task_id))
    return Task.model_validate(task)


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: int, session: AsyncSession = Depends(get_session)) -> None:
    task = await session.get(TaskORM, task_id)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    await session.delete(task)
    await session.commit()
    await cache_delete(TASKS_LIST_CACHE_KEY, _task_cache_key(task_id))
