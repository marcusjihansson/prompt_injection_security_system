import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class PendingRequest:
    future: asyncio.Future
    count: int


class RequestDeduplicator:
    """Deduplicate identical concurrent requests"""

    def __init__(self):
        self.pending: Dict[str, PendingRequest] = {}

    def _get_key(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    async def execute(self, text: str, handler):
        """Execute handler or wait for existing request"""
        key = self._get_key(text)

        if key in self.pending:
            # Request already in flight, wait for it
            self.pending[key].count += 1
            return await self.pending[key].future

        # Create new request
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending[key] = PendingRequest(future=future, count=1)

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler()
            else:
                # Run blocking handler in thread pool
                result = await loop.run_in_executor(None, handler)

            future.set_result(result)
            return result
        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            if key in self.pending:
                del self.pending[key]
