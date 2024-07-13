from dataclasses import dataclass
from typing import Any, Callable, Generic, Type, TypeVar

import pandas as pd

_EXTRACT_TYPE = TypeVar("_EXTRACT_TYPE")
_MAPPED_FIELD_NAME = str

EXTRACTOR = Callable[[Any], _EXTRACT_TYPE | None]


class Extractor(Generic[_EXTRACT_TYPE]):
    # Oh I tried, oh I tried to Type
    # And Oh, the Type broke me
    # Oh I tried, oh I tried to Type
    # And Oh, the Type broke me again
    # Maybe I'll be Trapped in a Type
    # Maybe the prophesized developer will come
    # The type gods will come
    # But not today, not today.
    # Today, I am just done.
    @staticmethod
    def create_extractor(
        cast_type: Type[_EXTRACT_TYPE],
    ) -> Callable[[Any], _EXTRACT_TYPE | None]:
        def get_value(row_value: Any) -> _EXTRACT_TYPE | None:
            if pd.isna(row_value) or not row_value:
                if cast_type is bool:
                    return False  # type: ignore [return-value]
                else:
                    return None  # type: ignore [return-value]
            else:
                if cast_type is str:
                    return str(row_value).strip()  # type: ignore [return-value]
                if cast_type is bool:
                    if isinstance(row_value, bool):
                        return row_value  # type: ignore [return-value]
                    if isinstance(row_value, str):
                        return (
                            row_value.strip().lower() != "false" and row_value.strip() != ""  # type: ignore [return-value] # noqa: E501
                        )

                    return bool(row_value)  # type: ignore [return-value]

                return cast_type(row_value)  # type: ignore [return-value, call-arg]

        return get_value


@dataclass
class SheetRecordSpec:
    extractor: EXTRACTOR
    mapped_field_name: _MAPPED_FIELD_NAME
