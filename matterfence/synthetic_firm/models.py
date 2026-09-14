from pydantic import BaseModel, Field


class User(BaseModel):
    id: str
    name: str
    role: str  # e.g., "Partner", "Associate", "Paralegal"


class Document(BaseModel):
    id: str
    matter_id: str
    title: str
    content: str
    is_privileged: bool = False


class Matter(BaseModel):
    id: str
    title: str
    client_name: str
    authorized_user_ids: list[str] = Field(default_factory=list)
    canary_token: str
    documents: list[Document] = Field(default_factory=list)

    def is_user_authorized(self, user_id: str) -> bool:
        """Returns True if the user is explicitly on the team for this matter."""
        return user_id in self.authorized_user_ids