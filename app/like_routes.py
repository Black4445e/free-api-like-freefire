from flask import Blueprint, request, jsonify
import asyncio
from datetime import datetime, timezone
import logging
import threading
import aiohttp
import requests
import time

from .utils.protobuf_utils import encode_uid, decode_info, create_protobuf
from .utils.crypto_utils import encrypt_aes
from .token_manager import get_headers
from byte import Encrypt_ID, encrypt_api

logger = logging.getLogger(__name__)

like_bp = Blueprint('like_bp', __name__)

_SERVERS = {}
_token_cache = None



async def async_post_request(url: str, data: bytes, token: str):
    try:
        headers = get_headers(token)
        print(f"[async_post_request] URL: {url} | Token: {token[:5]}... | Data length: {len(data)}")
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, headers=headers, timeout=10) as resp:
                resp_data = await resp.read()
                print(f"[async_post_request] Response status: {resp.status} | Response length: {len(resp_data)}")
                return resp_data
    except Exception as e:
        logger.error(f"Async request failed: {str(e)}")
        print(f"[async_post_request] Exception: {str(e)}")
        return None


def make_request(uid_enc: str, url: str, token: str):
    data = bytes.fromhex(uid_enc)
    headers = get_headers(token)
    print(f"[make_request] URL: {url} | Token: {token[:5]}... | Data length: {len(data)}")
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        print(f"[make_request] Response status: {response.status_code} | Content length: {len(response.content)}")
        if response.status_code == 200:
            decoded = decode_info(response.content)
            print(f"[make_request] Decoded player info: {decoded}")
            return decoded
        print(f"[make_request] Request failed with status {response.status_code}")
        return None
    except Exception as e:
        logger.error(f"Request error: {str(e)}")
        print(f"[make_request] Exception: {str(e)}")
        return None
        

async def detect_player_region(uid: str):
    print(f"[detect_player_region] Detecting region for UID: {uid}")
    for region_key, server_url in _SERVERS.items():
        tokens = _token_cache.get_tokens(region_key)
        print(f"[detect_player_region] Region: {region_key} | Tokens count: {len(tokens) if tokens else 0}")
        if not tokens:
            continue

        info_url = f"{server_url}/GetPlayerPersonalShow"
        response = await async_post_request(info_url, bytes.fromhex(encode_uid(uid)), tokens[0])
        if response:
            player_info = decode_info(response)
            print(f"[detect_player_region] Player info found in region {region_key}: {player_info}")
            if player_info and player_info.AccountInfo.PlayerNickname:
                return region_key, player_info
    print("[detect_player_region] Player region not found")
    return None, None


async def send_likes(uid: str, region: str):
    tokens = _token_cache.get_tokens(region)
    like_url = f"{_SERVERS[region]}/LikeProfile"
    encrypted = encrypt_aes(create_protobuf(uid, region))
    print(f"[send_likes] Sending likes for UID: {uid} in region: {region} | Tokens: {len(tokens)}")
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            async_post_request_with_session(session, like_url, bytes.fromhex(encrypted), token)
            for token in tokens
        ]
        results = await asyncio.gather(*tasks)
    print(f"[send_likes] Likes sent: {len(results)} | Successful adds: {sum(1 for r in results if r is not None)}")
    return {
        'sent': len(results),
        'added': sum(1 for r in results if r is not None)
    }

async def async_post_request_with_session(session, url, data, token):
    try:
        headers = get_headers(token)
        print(f"[async_post_request_with_session] URL: {url} | Token: {token[:5]}... | Data length: {len(data)}")
        async with session.post(url, data=data, headers=headers, timeout=10) as resp:
            resp_data = await resp.read()
            print(f"[async_post_request_with_session] Response status: {resp.status} | Response length: {len(resp_data)}")
            return resp_data
    except Exception as e:
        logger.error(f"Async request failed: {str(e)}")
        print(f"[async_post_request_with_session] Exception: {str(e)}")
        return None


@like_bp.route("/report/nickname", methods=["POST"])
async def report_nickname_abuse():
    try:
        data = request.get_json()
        print(f"[report_nickname_abuse] Received data: {data}")
        uid = data.get("uid")
        region = data.get("region")

        if not uid or not uid.isdigit():
            print("[report_nickname_abuse] Invalid UID")
            return jsonify({"error": "Invalid UID", "status": 400}), 400

        if not region or region not in _SERVERS:
            print("[report_nickname_abuse] Invalid region")
            return jsonify({
                "error": "Invalid region",
                "message": f"Supported regions: {', '.join(_SERVERS.keys())}",
                "status": 400
            }), 400

        tokens = _token_cache.get_tokens(region)
        print(f"[report_nickname_abuse] Tokens count for region {region}: {len(tokens) if tokens else 0}")
        if not tokens:
            return jsonify({"error": "No tokens available", "status": 400}), 400

        info_url = f"{_SERVERS[region]}/GetPlayerPersonalShow"
        player_info = make_request(encode_uid(uid), info_url, tokens[0])
        if not player_info:
            print("[report_nickname_abuse] Player not found")
            return jsonify({"error": "Player not found", "status": 404}), 404

        token = player_info.AccountInfo.NicknameAbuseReportToken
        if not token:
            print("[report_nickname_abuse] No report token found")
            return jsonify({"error": "No report token found", "status": 400}), 400

        # Monta e envia a denúncia
        fields = [
            {'tag': 1, 'wire_type': 0, 'value': int(uid)},
            {'tag': 2, 'wire_type': 2, 'value': token},
            {'tag': 3, 'wire_type': 0, 'value': 1},  # tipo 1 = nickname ofensivo
        ]
        protobuf_bytes = build_protobuf(fields)
        encrypted = encrypt_aes(protobuf_bytes)
        report_url = f"{_SERVERS[region]}/ReportNicknameAbuse"

        print(f"[report_nickname_abuse] Sending report to {report_url}")
        resp = requests.post(report_url, data=bytes.fromhex(encrypted), headers=get_headers(tokens[0]))
        print(f"[report_nickname_abuse] Response status: {resp.status_code} | Content length: {len(resp.content)}")
        return jsonify({
            "uid_reported": uid,
            "nickname": player_info.AccountInfo.PlayerNickname,
            "status_code": resp.status_code,
            "response": resp.content.hex(),
            "credits": "https://t.me/nopethug"
        })

    except Exception as e:
        logger.error(f"Report error: {str(e)}", exc_info=True)
        print(f"[report_nickname_abuse] Exception: {str(e)}")
        return jsonify({"error": str(e), "status": 500}), 500


@like_bp.route("/like", methods=["GET"])
async def like_player():
    try:
        uid = request.args.get("uid")
        region = request.args.get("region")
        print(f"[like_player] UID: {uid} | Region: {region}")

        if not uid or not uid.isdigit():
            print("[like_player] Invalid UID")
            return jsonify({
                "error": "Invalid UID",
                "message": "Valid numeric UID required",
                "status": 400,
                "credits": "https://t.me/nopethug"
            }), 400

        if not region or region not in _SERVERS:
            print("[like_player] Invalid region")
            return jsonify({
                "error": "Invalid region",
                "message": f"Supported regions: {', '.join(_SERVERS.keys())}",
                "status": 400,
                "credits": "https://t.me/nopethug"
            }), 400

        tokens = _token_cache.get_tokens(region)
        print(f"[like_player] Tokens count: {len(tokens) if tokens else 0}")
        info_url = f"{_SERVERS[region]}/GetPlayerPersonalShow"
        player_info = make_request(encode_uid(uid), info_url, tokens[0]) if tokens else None

        if not player_info:
            print("[like_player] Player not found")
            return jsonify({
                "error": "Player not found",
                "message": "Check UID or try a different region",
                "status": 404,
                "credits": "https://t.me/nopethug"
            }), 404

        before_likes = player_info.AccountInfo.Likes
        player_name = player_info.AccountInfo.PlayerNickname
        print(f"[like_player] Likes before: {before_likes} | Player name: {player_name}")

        await send_likes(uid, region)

        new_info = make_request(encode_uid(uid), info_url, tokens[0]) if tokens else None
        after_likes = new_info.AccountInfo.Likes if new_info else before_likes
        print(f"[like_player] Likes after: {after_likes}")

        return jsonify({
            "player": player_name,
            "uid": uid,
            "likes_added": after_likes - before_likes,
            "likes_before": before_likes,
            "likes_after": after_likes,
            "server_used": region,
            "status": 1 if after_likes > before_likes else 2,
            "credits": "https://t.me/nopethug"
        })

    except Exception as e:
        logger.error(f"Like error for UID {uid}: {str(e)}", exc_info=True)
        print(f"[like_player] Exception: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e),
            "status": 500,
            "credits": "https://t.me/nopethug"
        }), 500
        
        
def send_friend_request(uid, token, results):
    encrypted_id = Encrypt_ID(uid)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)

    url = "https://client.us.freefiremobile.com/RequestAddingFriend"
    headers = get_headers(token)

    try:
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False, timeout=10)
        if response.status_code == 200:
            results["success"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["failed"] += 1
        print(f"Request error: {e}")


@like_bp.route("/send_requests", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    tokens = _token_cache.get_tokens("BR")
    if not tokens:
        return jsonify({"error": "No valid tokens found in database"}), 500

    results = {"success": 0, "failed": 0}

    for token in tokens:
        send_friend_request(uid, token, results)
        # Removido o time.sleep(2) para enviar tudo de uma vez

    total_requests = results["success"] + results["failed"]
    status = 1 if results["success"] > 0 else 2

    return jsonify({
        "success_count": results["success"],
        "failed_count": results["failed"],
        "status": status,
        "total_tokens_used": total_requests,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@like_bp.route("/health-check", methods=["GET"])
def health_check():
    try:
        token_status = {
            server: len(_token_cache.get_tokens(server)) > 0
            for server in _SERVERS
        }
        print(f"[health_check] Token status: {token_status}")
        return jsonify({
            "status": "healthy" if all(token_status.values()) else "degraded",
            "servers": token_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "credits": "https://t.me/nopethug"
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        print(f"[health_check] Exception: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "credits": "https://t.me/nopethug"
        }), 500
        
@like_bp.route("/views", methods=["GET"])
async def simulate_profile_views():
    try:
        uid = request.args.get("uid")
        region = request.args.get("region")

        if not uid or not uid.isdigit():
            return jsonify({"error": "Invalid UID", "status": 400}), 400

        if not region or region not in _SERVERS:
            return jsonify({
                "error": "Invalid region",
                "message": f"Supported regions: {', '.join(_SERVERS.keys())}",
                "status": 400
            }), 400

        tokens = _token_cache.get_tokens(region)
        if not tokens:
            return jsonify({"error": "No tokens available", "status": 400}), 400

        info_url = f"{_SERVERS[region]}/GetPlayerPersonalShow"
        encrypted_uid = bytes.fromhex(encode_uid(uid))

        async with aiohttp.ClientSession() as session:
            tasks = [
                async_post_request_with_session(session, info_url, encrypted_uid, token)
                for token in tokens
            ]
            responses = await asyncio.gather(*tasks)

        success_count = sum(1 for r in responses if r is not None)
        sample_info = next((decode_info(r) for r in responses if r), None)

        return jsonify({
            "uid": uid,
            "region": region,
            "views_sent": len(tokens),
            "views_successful": success_count,
            "nickname": sample_info.AccountInfo.PlayerNickname if sample_info else "N/A",
            "likes": sample_info.AccountInfo.Likes if sample_info else "N/A",
            "status": "ok",
            "credits": "https://t.me/nopethug"
        })

    except Exception as e:
        logger.error(f"[simulate_profile_views] Error: {str(e)}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "message": str(e),
            "status": 500
        }), 500


@like_bp.route("/")
def home():
    return render_template("index.html")

def initialize_routes(app_instance, servers_config, token_cache_instance):
    global _SERVERS, _token_cache
    _SERVERS = servers_config
    _token_cache = token_cache_instance
    print("[initialize_routes] Routes initialized")
    app_instance.register_blueprint(like_bp)
