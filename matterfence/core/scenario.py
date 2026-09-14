from importlib.resources import files
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from matterfence.synthetic_firm.models import Matter, User

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class CrossMatterScenario(BaseModel):
    """Version 1 contract for one actor searching a synthetic matter collection."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: NonEmptyText
    version: Literal["1.0"]
    description: NonEmptyText
    threat_category: Literal["cross_matter_retrieval"]
    users: list[User] = Field(min_length=1)
    actor_id: NonEmptyText
    matters: list[Matter] = Field(min_length=2)
    prohibited_document_ids: list[NonEmptyText] = Field(min_length=1)
    attack: NonEmptyText
    expected_behavior: NonEmptyText
    evaluator: Literal["authorization_canary_v1"] = "authorization_canary_v1"
    severity: Literal["critical"] = "critical"

    @model_validator(mode="after")
    def validate_environment(self) -> Self:
        """Reject ambiguous identities, permissions, resources, and canary locations."""
        user_ids = [user.id for user in self.users]
        matter_ids = [matter.id for matter in self.matters]
        documents = [doc for matter in self.matters for doc in matter.documents]
        for ids in (user_ids, matter_ids, [doc.id for doc in documents]):
            if any(not item.strip() for item in ids) or len(ids) != len(set(ids)):
                raise ValueError(
                    "User, matter, and document IDs must be nonempty and unique"
                )
        if self.actor_id not in user_ids:
            raise ValueError("The actor must reference a declared user")

        allowed_matters = [
            matter
            for matter in self.matters
            if matter.is_user_authorized(self.actor_id)
        ]
        if not allowed_matters:
            raise ValueError("The actor must have at least one authorized matter")

        for matter in self.matters:
            permission_ids = (
                matter.authorized_user_ids
                + matter.screened_user_ids
                + matter.privileged_user_ids
            )
            if not set(permission_ids).issubset(user_ids):
                raise ValueError("Permissions must reference declared users")
            if any(doc.matter_id != matter.id for doc in matter.documents):
                raise ValueError("Each document must belong to its containing matter")

        forbidden_documents = [
            doc
            for matter in self.matters
            if not matter.is_user_authorized(self.actor_id)
            for doc in matter.documents
        ]
        prohibited_ids = self.prohibited_document_ids
        if len(prohibited_ids) != len(set(prohibited_ids)) or set(prohibited_ids) != {
            doc.id for doc in forbidden_documents
        }:
            raise ValueError(
                "Prohibited resources must name all and only denied-matter documents"
            )

        tokens = [matter.canary_token for matter in self.matters]
        if any(not token.strip() for token in tokens) or len(tokens) != len(
            set(tokens)
        ):
            raise ValueError("Matter canaries must be nonempty and distinct")
        readable_documents = [
            doc
            for matter in allowed_matters
            for doc in matter.documents
            if not doc.is_privileged or matter.is_user_privileged(self.actor_id)
        ]
        if not readable_documents:
            raise ValueError(
                "Include a readable document as a permitted-retrieval control"
            )
        for matter in self.matters:
            if matter.is_user_authorized(self.actor_id):
                continue
            token = matter.canary_token
            if any(token not in doc.content for doc in matter.documents):
                raise ValueError(
                    "Every prohibited document must contain its matter canary"
                )
            if token in self.attack or any(
                token in doc.content for doc in readable_documents
            ):
                raise ValueError(
                    "Forbidden canaries must not appear in the attack or "
                    "readable documents"
                )
        return self


def load_auth_scenario(path: Path | None = None) -> CrossMatterScenario:
    """Read UTF-8 JSON from a path, or the packaged example, and validate it."""
    source = (
        path
        if path is not None
        else files("matterfence.core").joinpath("mf_auth_001.json")
    )
    return CrossMatterScenario.model_validate_json(source.read_text(encoding="utf-8"))
