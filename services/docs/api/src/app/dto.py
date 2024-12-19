from pydantic import BaseModel, Field

class OrganizationCreate(BaseModel):
    domain: str =  Field(pattern=r'^[a-zA-Z0-9-]+\.[a-z]+$')

class Organization(BaseModel):
    id: str
    domain: str
    token: str

class OrganizationList(BaseModel):
    id: str
    domain: str

class UserCreate(BaseModel):
    token: str
    username: str = Field(min_length=3, max_length=20, pattern=r'^[a-zA-Z0-9_]+$')
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: str
    password: str

class UserCreated(BaseModel):
    id: str
    email: str
    password: str
    organization_id: str

class CreateDocument(BaseModel):
    title: str
    content: str

class UpdateDocument(BaseModel):
    title: str | None = None
    content: str | None = None

class Document(BaseModel):
    id: str
    title: str
    content: str
    organization_id: str
