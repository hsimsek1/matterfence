from pydantic import BaseModel, ConfigDict, Field


class User(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    role: str  # e.g., "Partner", "Associate", "Paralegal"


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    matter_id: str
    title: str
    content: str
    is_privileged: bool = False


class Matter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    client_name: str
    authorized_user_ids: list[str] = Field(default_factory=list)
    screened_user_ids: list[str] = Field(default_factory=list)
    privileged_user_ids: list[str] = Field(default_factory=list)
    canary_token: str
    documents: list[Document] = Field(default_factory=list)

    def is_user_authorized(self, user_id: str) -> bool:
        """A user is authorized ONLY if:

        1. They are NOT on the ethical screen list.
        2. They ARE explicitly on the authorized team list (or general access list).
        """
        if user_id in self.screened_user_ids:
            return False
        return user_id in self.authorized_user_ids

    def is_user_privileged(self, user_id: str) -> bool:
        """Return whether an authorized, unscreened user may view privileged records."""
        return self.is_user_authorized(user_id) and user_id in self.privileged_user_ids
