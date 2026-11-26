from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


@dataclass(frozen=True, slots=True)
class ParsedMail:
    subject: str
    body: str


class HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in ("br", "p", "div", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        elif tag in ("p", "div", "li"):
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)

    def get_text(self) -> str:
        return "".join(self.parts).strip()


def parse_email(raw: bytes) -> ParsedMail:
    if not raw:
        raise ValueError("Empty email")

    message = BytesParser(policy=policy.default).parsebytes(raw)

    subject = str(message.get("Subject", "")).strip()
    subject = subject or "(no subject)"

    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    if plain_parts:
        body = "\n".join(plain_parts).strip()
    elif html_parts:
        extractor = HTMLTextExtractor()
        extractor.feed("\n".join(html_parts))
        body = extractor.get_text()
    else:
        body = ""

    return ParsedMail(subject=subject[:998], body=body)
