from abc import ABC
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.types import TypeDecorator
import json

DeliverooBase = declarative_base()


class DictType(TypeDecorator, ABC):
    impl = Text()

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class DeliverooUser(DeliverooBase):
    __tablename__ = "user"

    discord_id = Column(String)
    basket = Column(DictType)
    wii_id = Column(Integer, primary_key=True, unique=True)
    email = Column(String)
    password = Column(String)
    auth_token = Column(String)
    roo_uid = Column(String)
    payment_id = Column(String)
