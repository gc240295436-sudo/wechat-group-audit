"""Format-independent records and stable, account-scoped report identities."""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import blake2b
import unicodedata


class AuditError(Exception):
    """An actionable error whose text contains no key material or raw records."""


def compact(value: str | None) -> str:
    return " ".join((value or "").split())


def search_form(value: str) -> str:
    return unicodedata.normalize("NFKC", compact(value)).translate({0xFE0E: None, 0xFE0F: None}).casefold()


def identity(category: str, value: str, account: str = "") -> str:
    digest = blake2b(digest_size=12, person=b"WGA-v1")
    for part in (category, account, value):
        data = part.encode("utf-8")
        digest.update(len(data).to_bytes(4, "big"))
        digest.update(data)
    return f"{category}-{digest.hexdigest()}"


@dataclass(frozen=True)
class Person:
    user: str
    nickname: str = ""
    remark: str = ""
    alias: str = ""
    kind: str = "other"

    @property
    def label(self) -> str:
        return compact(self.remark) or compact(self.nickname) or "（空白昵称）"


@dataclass(frozen=True)
class Room:
    user: str
    title: str
    members: tuple[str, ...]
    complete: bool = True
    declared_size: int | None = None

    @property
    def key(self) -> str:
        return identity("room", self.user)


@dataclass
class Directory:
    owner: str
    people: dict[str, Person]
    rooms: list[Room]
    evidence: dict = field(default_factory=dict)

    def resolve_owner(self, supplied: str | None) -> None:
        value = compact(supplied) if supplied else self.owner
        if not value:
            raise AuditError("请通过 --me 指定本人账号或微信号。")
        hits = [p for p in self.people.values() if p.user == value]
        if not hits:
            hits = [p for p in self.people.values() if p.alias and p.alias == value]
        if len(hits) != 1:
            raise AuditError("本人身份无法唯一匹配，请核对所选账号及 --me。")
        if self.owner and self.owner != hits[0].user:
            raise AuditError("本人身份与输入数据声明的账号不一致。")
        self.owner = hits[0].user

    def choose(self, selectors: list[str]) -> list[Room]:
        if not 1 <= len(selectors) <= 64:
            raise AuditError("每次请选择 1–64 个群。")
        chosen = []
        for text in selectors:
            if not compact(text):
                raise AuditError("群名不能为空。")
            direct = [r for r in self.rooms if text in (r.key, r.user)]
            matches = direct or [r for r in self.rooms if search_form(r.title) == search_form(text)]
            if len(matches) != 1:
                raise AuditError("群不存在或有同名候选，请先用 rooms 获取精确群 ID。")
            room = matches[0]
            if room in chosen:
                raise AuditError("同一个群不能重复选择。")
            if not room.complete or not room.members:
                raise AuditError("目标群的完整成员关系尚不可用，无法判断哪些好友未入群。")
            if len(set(room.members)) != len(room.members):
                raise AuditError("目标群存在重复成员记录，请重新取得一致的数据。")
            if any(user not in self.people for user in room.members):
                raise AuditError("目标群存在无法解析的成员身份，已停止分析。")
            if room.declared_size is not None and room.declared_size != len(room.members):
                raise AuditError("目标群的声明人数与实际成员记录不符。")
            chosen.append(room)
        return chosen
