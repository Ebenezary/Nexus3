import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from eth_account import Account
from eth_account.messages import encode_defunct
from ecies.utils import generate_key
import re
from TempMail import TempMail
from curl_cffi import requests as curl_requests
import nexus_pb2
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

REGISTRATION_MODE = True

ENVIRONMENT_ID = "adc09cea-6194-4667-8be8-931cc28dacd2"
BASE_URL = f"https://app.dynamicauth.com/api/v0/sdk/{ENVIRONMENT_ID}"
NEXUS_URL = "https://beta.orchestrator.nexus.xyz/v3/users"
NODES_URL = "https://beta.orchestrator.nexus.xyz/v3/nodes"
PRIVATE_KEYS_FILE = "privatekeys.txt"
PROXY_FILE = "proxy.txt"
MAX_CONCURRENT_REQUESTS = 10  # Semaphore limit when using proxy

HEADERS = {
    "content-type": "application/json",
    "origin": "https://app.nexus.xyz",
    "referer": "https://app.nexus.xyz/",
}

NEXUS_HEADERS = {
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

def read_proxy():
    try:
        with open(PROXY_FILE, 'r') as file:
            proxy = file.read().strip()
            if not proxy:
                logger.warning(f"{PROXY_FILE} is empty")
                return None
            if not re.match(r'^http://(\S+@)?[\w.-]+:\d+$', proxy):
                logger.error(f"Invalid proxy format in {PROXY_FILE}: {proxy}")
                return None
            logger.info(f"Loaded proxy: {proxy}")
            return proxy
    except FileNotFoundError:
        logger.warning(f"{PROXY_FILE} not found")
        return None
    except Exception as e:
        logger.error(f"Error reading proxy from {PROXY_FILE}: {e}")
        return None

def read_private_keys():
    try:
        with open(PRIVATE_KEYS_FILE, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logger.error(f"File {PRIVATE_KEYS_FILE} not found")
        return []
    except Exception as e:
        logger.error(f"Error reading private keys: {e}")
        return []

def get_wallet_address(private_key):
    try:
        account = Account.from_key(private_key)
        return account.address
    except Exception as e:
        logger.error(f"Error deriving address from private key: {e}")
        return None

def generate_session_public_key():
    try:
        key = generate_key()
        public_key = key.public_key.format(compressed=True).hex()
        return f"03{public_key[2:]}"
    except Exception as e:
        logger.error(f"Error generating session public key: {e}")
        return None

def sign_message(private_key, message):
    try:
        encoded_message = encode_defunct(text=message)
        signed = Account.sign_message(encoded_message, private_key=private_key)
        return f"0x{signed.signature.hex()}"
    except Exception as e:
        logger.error(f"Error signing message: {e}")
        return None

def create_user_payload(uuid: str, wallet_address: str) -> bytes:
    user_request = nexus_pb2.UserRequest(
        uuid=uuid,
        walletAddress=wallet_address
    )
    return user_request.SerializeToString()

def create_node_payload(user_id: str, node_type: int = 1) -> bytes:
    node_request = nexus_pb2.NodeRequest(
        nodeType=node_type,
        userId=user_id
    )
    return node_request.SerializeToString()

async def connect(address, proxy=None):
    logger.info("Step 1: Sending connect request to API")
    payload = {
        "address": address,
        "chain": "EVM",
        "provider": "browserExtension",
        "walletName": "metamask",
        "authMode": "connect-and-sign"
    }
    try:
        async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
            response = await session.post(f"{BASE_URL}/connect", json=payload, headers=HEADERS)
            if response.status_code in (200, 202):
                logger.info("Connect request successful")
                return True
            logger.error(f"Failed to send connect request, status: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error sending connect request: {e}")
        return False

async def fetch_nonce(proxy=None):
    logger.info("Step 2: Fetching nonce from API")
    try:
        async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
            response = await session.get(f"{BASE_URL}/nonce", headers=HEADERS)
            if response.status_code == 200:
                data = response.json()
                logger.info("Nonce fetched successfully")
                return data.get("nonce")
            logger.error(f"Failed to fetch nonce, status: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error fetching nonce: {e}")
        return None

async def verify_wallet(private_key, nonce, address, proxy=None):
    logger.info("Step 3: Verifying wallet with signed message")
    try:
        message_to_sign = (
            f"app.nexus.xyz wants you to sign in with your Ethereum account:\n{address}\n\n"
            "Welcome to Nexus. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. "
            "Signing is a safe, gas-less transaction that does not in any way give Nexus permission to perform any transactions with your wallet.\n\n"
            "URI: https://app.nexus.xyz/\n"
            "Version: 1\n"
            "Chain ID: 393\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {datetime.now(timezone.utc).isoformat()[:-6]}Z\n"
            f"Request ID: {ENVIRONMENT_ID}"
        )
        signed_message = sign_message(private_key, message_to_sign)
        if not signed_message:
            logger.error("Failed to sign message")
            return None

        session_public_key = generate_session_public_key()
        if not session_public_key:
            logger.error("Failed to generate session public key")
            return None

        payload = {
            "signedMessage": signed_message,
            "messageToSign": message_to_sign,
            "publicWalletAddress": address,
            "chain": "EVM",
            "walletName": "metamask",
            "walletProvider": "browserExtension",
            "network": "393",
            "additionalWalletAddresses": [],
            "sessionPublicKey": session_public_key
        }

        retry_delay = 2  # seconds
        while True:
            try:
                async with curl_requests.AsyncSession(impersonate="chrome131_android", proxy=proxy) as session:
                    response = await session.post(f"{BASE_URL}/verify", json=payload, headers=HEADERS)
                    if response.status_code == 200:
                        logger.info("Wallet verified successfully")
                        return response.json()
                    elif response.status_code != 200:
                        logger.warning(f"Wrong Status: {response.status_code} Received, retrying after {retry_delay} seconds...")
                        await asyncio.sleep(retry_delay)
                        continue
                    else:
                        logger.error(f"Failed to verify wallet, status: {response.status_code}, response: {response.text}")
                        return None
            except Exception as e:
                logger.error(f"Error during wallet verification request: {e}")
                return None

    except Exception as e:
        logger.error(f"Error verifying wallet: {e}")
        return None

async def select_wallet(jwt, wallet_id, proxy=None):
    logger.info("Step 4: Selecting wallet")
    headers = HEADERS.copy()
    headers['authorization'] = f"Bearer {jwt}"
    payload = {"walletId": wallet_id}
    try:
        async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
            response = await session.put(f"{BASE_URL}/users/wallets/selection", json=payload, headers=headers)
            if response.status_code == 200:
                logger.info("Wallet selected successfully")
                return response.json()
            logger.error(f"Failed to select wallet, status: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error selecting wallet: {e}")
        return None

async def get_verification_code(email_address, token, proxy=None):
    logger.info(f"Step 7: Waiting for verification code at {email_address}")
    try:
        tmp = TempMail()
        start_time = time.time()
        timeout = 60  # seconds 
        check_interval = 5
        while time.time() - start_time < timeout:
            emails = tmp.getEmails(token)
            if emails:
                for email in emails:
                    body = getattr(email, 'body', '')
                    match = re.search(r'\b\d{6}\b', body)
                    if match:
                        logger.info("Verification code received")
                        return match.group(0)
            await asyncio.sleep(check_interval)
        logger.error("Timeout: No verification email received")
        return None
    except Exception as e:
        logger.error(f"Error fetching verification code: {e}")
        return None

async def submit_user_data(jwt, email_address, proxy=None):
    logger.info(f"Step 6: Submitting user data with email {email_address}")
    headers = HEADERS.copy()
    headers['authorization'] = f"Bearer {jwt}"
    payload = {
        "email": email_address,
        "metadata": {"Get Updates": ["0"]}
    }
    try:
        async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
            response = await session.put(f"{BASE_URL}/users", json=payload, headers=headers)
            if response.status_code == 200:
                logger.info("User data submitted successfully")
                return response.json()
            logger.error(f"Failed to submit user data, status: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error submitting user data: {e}")
        return None

async def verify_email(jwt, verification_uuid, verification_token, proxy=None):
    logger.info("Step 8: Verifying email with code")
    headers = HEADERS.copy()
    headers['authorization'] = f"Bearer {jwt}"
    payload = {
        "verificationUUID": verification_uuid,
        "verificationToken": verification_token
    }
    retry_delay = 2  # seconds
    while True:
        try:
            async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
                response = await session.post(f"{BASE_URL}/emailVerifications/verify", json=payload, headers=headers)
                if response.status_code == 200:
                    logger.info("Email verified successfully")
                    return response.json()
                elif response.status_code == 403:
                    logger.warning(f"Received 403 status, retrying after {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    logger.error(f"Failed to verify email, status: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            return None

async def check_user_not_exists(address: str, proxy=None) -> bool:
    logger.info(f"Checking if user exists for address {address}")
    url = f"https://beta.orchestrator.nexus.xyz/v3/users/{address}"
    max_retries = 15
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
                response = await session.get(url, headers=NEXUS_HEADERS)
                
                if response.status_code == 404:
                    logger.info(f"User not found for address {address} (status: 404)")
                    return True
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/octet-stream' in content_type:
                        response_data = response.content
                        response_str = response_data.decode('utf-8', errors='ignore')
                        match = re.search(r'\d+', response_str)
                        if match:
                            node_id = match.group(0)
                            logger.info(f"Extracted node ID {node_id} from response for address {address}")
                        else:
                            logger.info(f"No node ID found in response for address {address}, proceeding to create node")
                            return True 
                    else:
                        logger.info(f"Response for address {address} is not application/octet-stream (Content-Type: {content_type})")
                    return False
                
                logger.warning(f"Unexpected status {response.status_code} for address {address}, retrying ({attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                continue

        except Exception as e:
            logger.error(f"Error checking user for address {address} on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            continue

    logger.error(f"Failed to check user for address {address} after {max_retries} attempts")
    return False

async def create_node(user_id: str, proxy=None) -> bool:
    logger.info(f"Creating node for user {user_id}")
    payload = create_node_payload(user_id)
    max_retries = 15
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
                response = await session.post(NODES_URL, data=payload, headers=NEXUS_HEADERS)
                if response.status_code == 200:
                    response_data = response.content
                    node_response = nexus_pb2.NodeResponse()
                    node_response.ParseFromString(response_data)
                    node_id = node_response.nodeId
                    logger.info(f"Node created successfully with nodeId {node_id} for user {user_id}")
                    
                    try:
                        try:
                            with open('node_arrays.txt', 'r') as f:
                                node_array = json.load(f)
                                if not isinstance(node_array, list):
                                    logger.error("node_arrays.txt does not contain a valid JSON array, initializing new array")
                                    node_array = []
                        except FileNotFoundError:
                            logger.info("node_arrays.txt not found, initializing new array")
                            node_array = []
                        except json.JSONDecodeError:
                            logger.error("Invalid JSON in node_arrays.txt, initializing new array")
                            node_array = []
                        
                        if node_id not in node_array:
                            node_array.append(node_id)
                            with open('node_arrays.txt', 'w') as f:
                                json.dump(node_array, f, indent=2)
                            logger.info(f"Appended nodeId {node_id} to node_arrays.txt")
                        else:
                            logger.info(f"NodeId {node_id} already exists in node_arrays.txt, skipping")
                    except Exception as e:
                        logger.error(f"Error handling node_arrays.txt: {e}")
                    
                    return True
                
                logger.warning(f"Failed to create node for user {user_id}, status: {response.status_code}, response: {response.text}, retrying ({attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                continue
        
        except Exception as e:
            logger.error(f"Error creating node for user {user_id} on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            continue
    
    logger.error(f"Failed to create node for user {user_id} after {max_retries} attempts")
    return False

async def login_to_nexus(user_id, address, proxy=None):
    logger.info(f"Step 10: Logging into Nexus for user {user_id}")
    payload = create_user_payload(user_id, address)
    max_retries = 15
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
                response = await session.post(NEXUS_URL, data=payload, headers=NEXUS_HEADERS)
                if response.status_code == 200:
                    logger.info(f"Nexus login successful for user {user_id}")
                    return response.json()
                
                logger.warning(f"Failed to login to Nexus for user {user_id}, status: {response.status_code}, response: {response.text}, retrying ({attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                continue
        
        except Exception as e:
            logger.error(f"Error logging into Nexus for user {user_id} on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            continue
    
    logger.error(f"Failed to login to Nexus for user {user_id} after {max_retries} attempts")
    return None

async def process_private_key(private_key, proxy=None, semaphore=None):
    async def run_with_semaphore():
        async with semaphore:
            await _process_private_key(private_key, proxy)

    async def run_without_semaphore():
        await _process_private_key(private_key, proxy)

    if semaphore:
        return await run_with_semaphore()
    return await run_without_semaphore()

async def _process_private_key(private_key, proxy):
    logger.info("Starting wallet processing")
    address = get_wallet_address(private_key)
    if not address:
        logger.error("Invalid wallet address, skipping")
        return
    logger.info(f"Derived wallet address: {address}")

    if REGISTRATION_MODE:
        registration_status = await check_user_not_exists(address, proxy)
        if not registration_status:
            logger.info(f"User already exists for address {address}")
            max_retries = 15
            retry_delay = 2  # seconds
            for attempt in range(max_retries):
                try:
                    async with curl_requests.AsyncSession(impersonate="chrome120", proxy=proxy) as session:
                        response = await session.get(f"https://beta.orchestrator.nexus.xyz/v3/users/{address}", headers=NEXUS_HEADERS)
                        if response.status_code == 200:
                            content_type = response.headers.get('Content-Type', '')
                            if 'application/octet-stream' in content_type:
                                response_data = response.content
                                response_str = response_data.decode('utf-8', errors='ignore')
                                match = re.search(r'\d+', response_str)
                                if match:
                                    node_id = match.group(0)
                                    logger.info(f"Node ID {node_id} exists for address {address}, moving private key to registered_keys.txt")
                                    try:
                                        with open('privatekeys.txt', 'r') as f:
                                            private_keys = [line.strip() for line in f if line.strip()]
                                        
                                        if private_key in private_keys:
                                            private_keys.remove(private_key)
                                            with open('privatekeys.txt', 'w') as f:
                                                f.write('\n'.join(private_keys) + '\n' if private_keys else '')
                                            logger.info(f"Removed private key for address {address} from privatekeys.txt")
                                        else:
                                            logger.warning(f"Private key for address {address} not found in privatekeys.txt")

                                        if os.path.exists('registered_keys.txt'):
                                            with open('registered_keys.txt', 'rb+') as f:
                                                f.seek(0, os.SEEK_END)
                                                file_size = f.tell()
                                                if file_size > 0:
                                                    f.seek(-1, os.SEEK_END)
                                                    last_char = f.read(1)
                                                    if last_char != b'\n':
                                                        f.write(b'\n')

                                        with open('registered_keys.txt', 'a', encoding='utf-8') as f:
                                            f.write(f"{private_key}\n")
                                        logger.info(f"Appended private key for address {address} to registered_keys.txt")
                                    except Exception as e:
                                        logger.error(f"Error moving private key for address {address}: {e}")
                                    return
                                logger.info(f"No node ID found for address {address}, proceeding to create node")
                            else:
                                logger.info(f"Response for address {address} is not application/octet-stream, proceeding to create node")
                            return
                        else:
                            logger.warning(f"Unexpected status {response.status_code} when checking user, retrying ({attempt + 1}/{max_retries})")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(retry_delay)
                            continue
                except Exception as e:
                    logger.error(f"Error checking user for address {address} on attempt {attempt + 1}/{max_retries}: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                    continue

            logger.error(f"Failed to check user for address {address} after {max_retries} attempts, skipping")
            return
        else:
            logger.info(f"User does not exist for address {address}, proceeding with registration")

    #: Connect
    if not await connect(address, proxy):
        logger.error("Connect request failed, skipping wallet")
        return

    #: Fetch nonce
    nonce = await fetch_nonce(proxy)
    if not nonce:
        logger.error("Failed to fetch nonce, skipping wallet")
        return

    #: Verify wallet
    verify_response = await verify_wallet(private_key, nonce, address, proxy)
    if not verify_response:
        logger.error("Wallet verification failed, skipping wallet")
        return

    jwt = verify_response.get("jwt")
    wallet_id = verify_response["user"]["verifiedCredentials"][0]["id"]

    #: Select wallet
    select_response = await select_wallet(jwt, wallet_id, proxy)
    if not select_response:
        logger.error("Wallet selection failed, skipping wallet")
        return

    #: Check if email verification is required
    if 'email' not in select_response.get('user', {}):
        logger.info("Email verification required for 'Get Updates' subscription")
        tmp = TempMail()
        inbox = tmp.createInbox()
        email_address = inbox.address
        token = inbox.token
        logger.info(f"Generated temporary email: {email_address}")

        #: Submit user data
        user_data_response = await submit_user_data(select_response["jwt"], email_address, proxy)
        if not user_data_response:
            logger.error("Failed to submit user data, skipping wallet")
            return

        verification_uuid = user_data_response.get("emailVerification", {}).get("verificationUUID")
        if not verification_uuid:
            logger.error("No verification UUID found, skipping wallet")
            return

        #: Get verification code
        verification_code = await get_verification_code(email_address, token, proxy)
        if not verification_code:
            logger.error("Failed to retrieve verification code, skipping wallet")
            return

        #: Verify email
        email_verify_response = await verify_email(user_data_response["jwt"], verification_uuid, verification_code, proxy)
        if not email_verify_response:
            logger.error("Email verification failed, skipping wallet")
            return

        final_response = email_verify_response
    else:
        logger.info("No email verification required")
        final_response = select_response

    user_id = final_response["user"]["id"]

    if registration_status:  # User didn't exist
        #: Login to Nexus to register user
        nexus_response = await login_to_nexus(user_id, address, proxy)
        if nexus_response is None:
            logger.error("Failed to login to Nexus, skipping wallet")
            return
        #: Create node
        if not await create_node(user_id, proxy):
            logger.error("Failed to create node, skipping wallet")
            return
    else:  # User exists, but no node ID
        #: Create node
        if not await create_node(user_id, proxy):
            logger.error("Failed to create node, skipping wallet")
            return

    logger.info(f"Completed processing for wallet {address}: Successfully logged into Nexus")

async def main():
    logger.info("Starting Nexus authentication process")
    private_keys = read_private_keys()
    if not private_keys:
        logger.error(f"No private keys found in {PRIVATE_KEYS_FILE}, exiting")
        return

    logger.info(f"Found {len(private_keys)} private keys to process")
    proxy = read_proxy()

    if proxy:
        logger.info(f"Using proxy {proxy} with concurrent processing (max {MAX_CONCURRENT_REQUESTS} tasks)")
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        tasks = [process_private_key(key, proxy, semaphore) for key in private_keys]
        await asyncio.gather(*tasks)
    else:
        logger.info("No proxy available, processing private keys sequentially")
        for key in private_keys:
            await process_private_key(key, proxy=None)
            await asyncio.sleep(1)

    logger.info("All wallets processed")

if __name__ == "__main__":
    asyncio.run(main())