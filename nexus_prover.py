import aiohttp
import asyncio
import nexus_pb2  
import os
import json


NODE_IDS_FILE = os.path.join(os.path.dirname(__file__), "node_arrays.txt")

try:
    with open(NODE_IDS_FILE, "r") as file:
        NODE_IDS = json.load(file)
        if not isinstance(NODE_IDS, list) or not all(isinstance(node_id, str) for node_id in NODE_IDS):
            raise ValueError("The file must contain a JSON array of strings.")
except Exception as e:
    print(f"Error reading NODE_IDS from {NODE_IDS_FILE}: {e}")
    NODE_IDS = []

TASK_URL = "https://beta.orchestrator.nexus.xyz/v3/tasks"
SUBMIT_URL = "https://beta.orchestrator.nexus.xyz/v3/tasks/submit"

HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Content-Type": "application/octet-stream",
    "Origin": "https://app.nexus.xyz",
    "Pragma": "no-cache",
    "Referer": "https://app.nexus.xyz/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
    ),
    "sec-ch-ua": '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

counters = {}

class RestartCycleSignal(Exception):
    pass

def create_task_payload(node_id: str) -> bytes:
    task_request = nexus_pb2.TaskRequest(
        nodeId=node_id,
        nodeType=0 
    )
    return task_request.SerializeToString()

def create_proof_payload(node_id: str, task_id: str) -> bytes:
    counter = counters.get(node_id, 0)
    if counter >= 30_000:
        counters[node_id] = 0
        counter = 0

    web_value = f"web-99-{counter}/100"
    proof_request = nexus_pb2.SubmitTaskRequest(
        nodeId=node_id,
        nodeType=0,
        proofHash=web_value,
        proof=web_value.encode('utf-8'),
        taskId=task_id,
        nodeTelemetry=nexus_pb2.NodeTelemetry(
            flopsPerSec=1,
            memoryUsed=1,
            memoryCapacity=1,
            location="US"
        )
    )

    counters[node_id] = counter + 100
    return proof_request.SerializeToString()

async def fetch_task(session, node_id: str) -> str | None:
    payload = create_task_payload(node_id)
    print(f"[{node_id}] Fetching task id...")

    try:
        async with session.post(TASK_URL, headers=HEADERS, data=payload) as response:
            if response.status != 200:
                return None

            response_data = await response.read()
            task_response = nexus_pb2.TaskResponse()
            task_response.ParseFromString(response_data)
            return task_response.taskId if task_response.taskId else None
    except Exception as e:
        print(f"[{node_id}] Error fetching task: {e}")
        return None

async def submit_proof(session, node_id: str, task_id: str) -> bool:
    retries = 0
    while retries < 5:
        payload = create_proof_payload(node_id, task_id)
        print(f"[{node_id}] Submitting proof for task id {task_id} (Attempt {retries + 1})...")

        try:
            async with session.post(SUBMIT_URL, headers=HEADERS, data=payload) as response:
                response_text = await response.text()
                print(f"[{node_id}] Submit response ({response.status}): {response_text}")
                if response.status == 200:
                    return True
        except Exception as e:
            print(f"[{node_id}] Error submitting proof: {e}")

        retries += 1
        print(f"[{node_id}] Retrying proof submission in 5 seconds...")
        await asyncio.sleep(5)

    print(f"[{node_id}] Failed to submit proof after {retries} attempts.")
    return False

async def task_proof_cycle(session, node_id: str):
    print(f"\n--- [Node {node_id}] Starting new cycle ---")
    task_id = await fetch_task(session, node_id)

    if not task_id:
        print(f"[{node_id}] No task ID received, retrying in 5 seconds...")
        await asyncio.sleep(5)
        return False 

    success = await submit_proof(session, node_id, task_id)
    if not success:
        print(f"[{node_id}] Proof submission failed.")

    return True

async def run_task_cycle_forever(session, node_id: str):
    while True:
        completed = await task_proof_cycle(session, node_id)

        if completed:
            await asyncio.sleep(150)  # Full cycle done, wait 2m30s
        else:
            pass


async def main():
    for node_id in NODE_IDS:
        counters[node_id] = 0

    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*(run_task_cycle_forever(session, node_id) for node_id in NODE_IDS))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScript terminated by user.")