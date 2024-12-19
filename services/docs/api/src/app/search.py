import httpx

from app.config import settings


class SearchClient:
    def __init__(self, host):
        self.host = host
        self.client = httpx.AsyncClient()

    async def search(self, query, org_id) -> list[str]:
        response = await self.client.get(
            f"{self.host}/search?q={query}&org_id={org_id}"
        )
        if response.status_code != 200:
            return []
        response = response.json()
        return [x.get('id') for x in response.get('hits')]

    async def index(self, doc_id: str, title: str, content: str, org_id: str):
        body = {
            'id': doc_id,
            'title': title,
            'content': content,
            'org_id': org_id
        }
        response = await self.client.post(f'{self.host}/index', json=body)
        response.raise_for_status()

