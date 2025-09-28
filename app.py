from flask import Flask, request, jsonify
import requests
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2
from byte import Encrypt_ID, encrypt_api
import telebot
import jwt

app = Flask(__name__)
bot = telebot.TeleBot("7819546201:AAFygncq5TTfcWyBXtJN3g1-HBRyXZHkfe8")
bot.remove_webhook()
bot.set_webhook(url="https://tcp-friend-bot.onrender.com/webhook")

CURRENT_VERSION = "OB50"
UNITY_VERSION = "2020.3.18f1"
BOT_UID = "4181697804"
BOT_PASSWORD = "078C96EEA2DE3287F194E37164E675BA4EBC09A02BACD9A188A58B8EE33127AE"

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def get_region_endpoint(region):
    region = region.upper()
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    elif region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com"
    else:
        return "https://clientbp.ggblueshark.com"

def make_request(encrypt, region, token):
    try:
        base_url = get_region_endpoint(region)
        url = f"{base_url}/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; SM-G988B Build/SP1A.210812.016)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': UNITY_VERSION,
            'X-GA': "v1 1",
            'ReleaseVersion': CURRENT_VERSION
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        return decode
    except:
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

def send_friend_request(uid, token, region, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        base_url = get_region_endpoint(region)
        url = f"{base_url}/RequestAddingFriend"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": UNITY_VERSION,
            "X-GA": "v1 1",
            "ReleaseVersion": CURRENT_VERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G988B Build/SP1A.210812.016)",
            "Host": "clientbp.ggblueshark.com" if region not in ["IND", "BR", "US", "SAC", "NA"] else "client.us.freefiremobile.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=5)
        if response.status_code == 200:
            results["success"] += 1
        else:
            results["failed"] += 1
    except:
        results["failed"] += 1

def generate_token(uid, password):
    try:
        url = f"https://jwt-api-woad.vercel.app/token?uid={uid}&password={password}&key=Shahil440"
        response = requests.get(url)
        data = response.json()
        return data.get("token")
    except:
        return None

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except:
        return None

def get_player_info_api(uid, region):
    try:
        url = f"https://shahilxinfo.vercel.app/player-info?uid={uid}&region={region.lower()}"
        response = requests.get(url, timeout=10)
        return response.json()
    except:
        return None

@app.route("/send_requests", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return jsonify({"error": "uid and region are required"}), 400
    token = generate_token(BOT_UID, BOT_PASSWORD)
    if not token:
        return jsonify({"error": "Failed to generate token"}), 500
    try:
        player_data = get_player_info_api(uid, region)
        if player_data:
            player_name = player_data.get("data", {}).get("basicInfo", {}).get("nickname", "Unknown")
            player_uid = player_data.get("data", {}).get("basicInfo", {}).get("accountId", 0)
            player_level = player_data.get("data", {}).get("basicInfo", {}).get("level", 0)
        else:
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")
            info = make_request(encrypted_uid, region, token)
            if info is None:
                raise Exception("Failed to retrieve player info.")
            jsone = MessageToJson(info)
            data_info = json.loads(jsone)
            player_uid = int(data_info.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_info.get('AccountInfo', {}).get('PlayerNickname', 'Unknown'))
            player_level = int(data_info.get('AccountInfo', {}).get('Level', 0))
    except:
        player_uid = 0
        player_name = "Unknown"
        player_level = 0
    results = {"success": 0, "failed": 0}
    send_friend_request(uid, token, region, results)
    status = 1 if results["success"] > 0 else 2 if results["failed"] > 0 else 0
    return jsonify({
        "status": status,
        "success_count": results["success"],
        "failed_count": results["failed"],
        "player_info": {
            "nickname": player_name,
            "uid": player_uid,
            "level": player_level
        },
        "version": CURRENT_VERSION
    })

@app.route('/info', methods=['GET'])
def get_player_info():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return jsonify({"error": "UID and region are required"}), 400
    try:
        player_data = get_player_info_api(uid, region)
        if player_data:
            basic_info = player_data.get("data", {}).get("basicInfo", {})
            response = {
                "status": 1,
                "data": {
                    "basic": {
                        "nickname": basic_info.get("nickname", "Unknown"),
                        "uid": basic_info.get("accountId", 0),
                        "level": basic_info.get("level", 0),
                        "experience": basic_info.get("exp", 0)
                    },
                    "stats": {
                        "total_matches": basic_info.get("totalMatches", 0),
                        "total_kills": basic_info.get("totalKills", 0),
                        "kda": basic_info.get("kda", 0),
                        "win_rate": basic_info.get("winRate", 0)
                    }
                },
                "version": CURRENT_VERSION
            }
            return jsonify(response)
        else:
            token = generate_token(BOT_UID, BOT_PASSWORD)
            if not token:
                return jsonify({"error": "Failed to generate token"}), 500
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                return jsonify({"error": "UID encryption failed"}), 500
            info = make_request(encrypted_uid, region, token)
            if info is None:
                return jsonify({"error": "Failed to retrieve player info"}), 404
            jsone = MessageToJson(info)
            data_info = json.loads(jsone)
            response = {
                "status": 1,
                "data": {
                    "basic": {
                        "nickname": data_info.get('AccountInfo', {}).get('PlayerNickname', 'Unknown'),
                        "uid": data_info.get('AccountInfo', {}).get('UID', 0),
                        "level": data_info.get('AccountInfo', {}).get('Level', 0),
                        "experience": data_info.get('AccountInfo', {}).get('Experience', 0)
                    },
                    "stats": {
                        "total_matches": data_info.get('AccountInfo', {}).get('TotalMatches', 0),
                        "total_kills": data_info.get('AccountInfo', {}).get('TotalKills', 0),
                        "kda": data_info.get('AccountInfo', {}).get('KDA', 0),
                        "win_rate": data_info.get('AccountInfo', {}).get('WinRate', 0)
                    }
                },
                "version": CURRENT_VERSION
            }
            return jsonify(response)
    except Exception as e:
        return jsonify({
            "status": 0,
            "error": str(e),
            "version": CURRENT_VERSION
        }), 500

@app.route('/version', methods=['GET'])
def version_check():
    return jsonify({
        "status": 1,
        "current_version": CURRENT_VERSION,
        "unity_version": UNITY_VERSION,
        "supported_regions": ["IND", "BR", "US", "SAC", "NA", "BD", "ME", "EU"]
    })

@app.route('/webhook', methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_data().decode('utf-8')
        update = telebot.types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    else:
        return 'Invalid content type', 403

@bot.message_handler(commands=['add'])
def handle_add_command(message):
    try:
        uid = message.text.split()[1]
        region = "IND"
        token = generate_token(BOT_UID, BOT_PASSWORD)
        if not token:
            bot.reply_to(message, "❌ Failed to generate token")
            return
        
        jwt_data = decode_jwt(token)
        bot_name = jwt_data.get("nickname", "Unknown") if jwt_data else "Unknown"
        
        player_data = get_player_info_api(uid, region)
        if player_data:
            basic_info = player_data.get("data", {}).get("basicInfo", {})
            player_name = basic_info.get("nickname", "Unknown")
            player_uid = basic_info.get("accountId", 0)
            player_level = basic_info.get("level", 0)
        else:
            encrypted_uid = enc(uid)
            if not encrypted_uid:
                bot.reply_to(message, "❌ UID encryption failed")
                return
            info = make_request(encrypted_uid, region, token)
            if not info:
                bot.reply_to(message, "❌ Failed to retrieve player info")
                return
            jsone = MessageToJson(info)
            data_info = json.loads(jsone)
            player_name = str(data_info.get('AccountInfo', {}).get('PlayerNickname', 'Unknown'))
            player_uid = int(data_info.get('AccountInfo', {}).get('UID', 0))
            player_level = int(data_info.get('AccountInfo', {}).get('Level', 0))
        
        results = {"success": 0, "failed": 0}
        send_friend_request(uid, token, region, results)
        
        response_text = "🎯 *FRIEND REQUEST SENT* 🎯\n\n"
        response_text += "🤖 *Bot Account:*\n"
        response_text += f"   └─ 🔖 {bot_name}\n\n"
        response_text += "👤 *Target Player:*\n"
        response_text += f"   ├─ 🆔 UID: `{player_uid}`\n"
        response_text += f"   ├─ 🏷️ Name: {player_name}\n"
        response_text += f"   └─ ⭐ Level: {player_level}\n\n"
        response_text += "📊 *Request Results:*\n"
        response_text += f"   ├─ ✅ Successful: {results['success']}\n"
        response_text += f"   └─ ❌ Failed: {results['failed']}\n\n"
        response_text += "💫 *Please accept the friend request from the bot account*"
        
        bot.reply_to(message, response_text, parse_mode='Markdown')
        
    except IndexError:
        bot.reply_to(message, "📝 *Usage:* `/add <uid>`\nExample: `/add 1234567890`", parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {str(e)}", parse_mode='Markdown')

@bot.message_handler(commands=['help', 'start'])
def handle_help_command(message):
    help_text = "🤖 *FREE FIRE FRIEND REQUEST BOT* 🤖\n\n"
    help_text += "📋 *Available Commands:*\n"
    help_text += "   └─ `/add <uid>` - Send friend requests to a player\n"
    help_text += "   └─ `/help` - Show this help message\n\n"
    help_text += "⚡ *Features:*\n"
    help_text += "   └─ Single account request sending\n"
    help_text += "   └─ Player information lookup\n"
    help_text += "   └─ Automatic bot account management\n\n"
    help_text += "🎮 *Version:* OB50"
    bot.reply_to(message, help_text, parse_mode='Markdown')

@bot.message_handler(commands=['stats'])
def handle_stats_command(message):
    try:
        uid = message.text.split()[1]
        region = "IND"
        
        player_data = get_player_info_api(uid, region)
        if player_data:
            basic_info = player_data.get("data", {}).get("basicInfo", {})
            player_name = basic_info.get("nickname", "Unknown")
            player_uid = basic_info.get("accountId", 0)
            player_level = basic_info.get("level", 0)
            total_matches = basic_info.get("totalMatches", 0)
            total_kills = basic_info.get("totalKills", 0)
            kda = basic_info.get("kda", 0)
            win_rate = basic_info.get("winRate", 0)
        else:
            token = generate_token(BOT_UID, BOT_PASSWORD)
            if not token:
                bot.reply_to(message, "❌ Failed to generate token")
                return
            encrypted_uid = enc(uid)
            if not encrypted_uid:
                bot.reply_to(message, "❌ UID encryption failed")
                return
            info = make_request(encrypted_uid, region, token)
            if not info:
                bot.reply_to(message, "❌ Failed to retrieve player info")
                return
            jsone = MessageToJson(info)
            data_info = json.loads(jsone)
            player_name = str(data_info.get('AccountInfo', {}).get('PlayerNickname', 'Unknown'))
            player_uid = int(data_info.get('AccountInfo', {}).get('UID', 0))
            player_level = int(data_info.get('AccountInfo', {}).get('Level', 0))
            total_matches = int(data_info.get('AccountInfo', {}).get('TotalMatches', 0))
            total_kills = int(data_info.get('AccountInfo', {}).get('TotalKills', 0))
            kda = float(data_info.get('AccountInfo', {}).get('KDA', 0))
            win_rate = float(data_info.get('AccountInfo', {}).get('WinRate', 0))
        
        stats_text = "📊 *PLAYER STATISTICS* 📊\n\n"
        stats_text += f"👤 *Player:* {player_name}\n"
        stats_text += f"🆔 *UID:* `{player_uid}`\n"
        stats_text += f"⭐ *Level:* {player_level}\n\n"
        stats_text += "🎮 *Game Stats:*\n"
        stats_text += f"   ├─ 🎯 Total Matches: {total_matches}\n"
        stats_text += f"   ├─ 🔫 Total Kills: {total_kills}\n"
        stats_text += f"   ├─ 📈 K/D/A: {kda:.2f}\n"
        stats_text += f"   └─ 🏆 Win Rate: {win_rate:.2f}%\n\n"
        stats_text += "⚡ *Powered by TCP Bot System*"
        
        bot.reply_to(message, stats_text, parse_mode='Markdown')
        
    except IndexError:
        bot.reply_to(message, "📝 *Usage:* `/stats <uid>`\nExample: `/stats 1234567890`", parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {str(e)}", parse_mode='Markdown')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
