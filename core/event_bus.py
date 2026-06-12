import asyncio

class EventBus:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def publish(self, event):
        await self.queue.put(event)

    async def consume(self):
        return await self.queue.get()
