"""Extract comparison-friendly metadata from fetched HTML documents."""

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


class WebsiteParser:
    """Parse page metadata and normalize safe asset references.

    The parser does not fetch extracted assets; it only returns references
    resolved against the supplied base URL.
    """

    @staticmethod
    def _safe_reference(value: str, base_url: str):
        """Resolve a reference while rejecting active and local-file schemes."""
        if not value:
            return None

        value = value.strip()

        if value.lower().startswith(
            ("javascript:", "data:", "file:")
        ):
            return None

        absolute = urljoin(base_url, value)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            return None

        return absolute

    def parse(self, html: str, base_url: str) -> dict:
        """Extract normalized title, description, branding, and asset metadata."""
        soup = BeautifulSoup(html, "html.parser")

        title = (
            soup.title.get_text(" ", strip=True)
            if soup.title else None
        )

        description_tag = soup.find(
            "meta",
            attrs={"name": "description"},
        )

        description = (
            description_tag.get("content", "").strip()
            if description_tag else None
        )

        site_name_tag = soup.find(
            "meta",
            attrs={"property": "og:site_name"},
        )

        site_name = (
            site_name_tag.get("content", "").strip()
            if site_name_tag else None
        )

        favicon = None

        for link in soup.find_all("link", href=True):
            rel = link.get("rel", [])
            rel_text = " ".join(rel).lower()

            if "icon" in rel_text:
                favicon = self._safe_reference(
                    link.get("href"),
                    base_url,
                )
                if favicon:
                    break

        logo_candidates = []

        for image in soup.find_all("img"):
            description_text = " ".join([
                image.get("alt", ""),
                image.get("id", ""),
                " ".join(image.get("class", [])),
            ]).lower()

            if "logo" not in description_text:
                continue

            reference = self._safe_reference(
                image.get("src"),
                base_url,
            )

            if reference and reference not in logo_candidates:
                logo_candidates.append(reference)

            if len(logo_candidates) >= 10:
                break

        image_references = []

        for image in soup.find_all("img", src=True):
            reference = self._safe_reference(
                image.get("src"),
                base_url,
            )

            if reference and reference not in image_references:
                image_references.append(reference)

            if len(image_references) >= 20:
                break

        tag_sequence = [
            tag.name
            for tag in soup.find_all()
            if tag.name
        ][:500]

        return {
            "title": title,
            "description": description,
            "site_name": site_name,
            "favicon": favicon,
            "logo_candidates": logo_candidates,
            "image_references": image_references,
            "tag_sequence": tag_sequence,
        }