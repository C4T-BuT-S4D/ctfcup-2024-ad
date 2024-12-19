from beanie import Document


class User(Document):
    username: str
    password: str
    organization_id: str

    class Settings:
        name = "users"


class Organization(Document):
    domain: str
    token: str

    class Settings:
        name = "organizations"


class Doc(Document):
    title: str
    author_id: str
    content: str
    organization_id: str

    class Settings:
        name = "documents"
