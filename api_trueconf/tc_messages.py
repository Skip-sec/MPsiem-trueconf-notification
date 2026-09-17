import os 
import json 
import asyncio 
import logging 
import websockets 
import ssl 

_active_websocket = None 
_request_id = 1 

async def init_trueconf_connection(token): 
    """ 
    Устанавливает долгоживущее WebSocket соединение и запускает слушателя.
    """ 
    global _active_websocket, _request_id 
    logging.info("Инициализация долгоживущего WebSocket соединения с TrueConf...") 
 
    ws_url = os.getenv("TRUECONF_WS_URL") 
    if not ws_url: 
        logging.error("В конфигурации .env отсутствует переменная TRUECONF_WS_URL") 
        return False 
        
    ssl_context = ssl.create_default_context() 
    ssl_context.check_hostname = False 
    ssl_context.verify_mode = ssl.CERT_NONE 
    
    try: 
        _active_websocket = await websockets.connect( 
            ws_url, 
            ssl=ssl_context, 
            subprotocols=["json.v1"] 
        ) 
 
        auth_payload = { 
            "type": 1, 
            "id": 1, 
            "method": "auth", 
            "payload": { 
                "token": token, 
                "tokenType": "JWT", 
                "receiveUnread": False, 
                "receiveSystemMessageEnvelopes": True 
            } 
        } 
        await _active_websocket.send(json.dumps(auth_payload)) 
 
        # Запускаем фоновую задачу прослушивания в рамках текущего Event Loop 
        asyncio.create_task(_listen_incoming_stream()) 
        return True 
 
    except Exception as err: 
        logging.error(f"Не удалось установить фоновое WebSocket соединение: {err}") 
        _active_websocket = None 
        return False 

async def _listen_incoming_stream(): 
    """ 
    Фоновый обработчик. Гасит системный флуд сервера (лимиты и т.д.)
    """ 
    global _active_websocket 
    logging.info("Фоновый слушатель сокета TrueConf успешно запущен.")
 
    try: 
        async for raw_msg in _active_websocket: 
            msg = json.loads(raw_msg) 
            resp_type = msg.get("type") 
            resp_id = msg.get("id") 
 
            if resp_type == 1: 
                sys_method = msg.get("method") 
                logging.info(f"[Слушатель] Получен системный запрос '{sys_method}' (id: {resp_id}). Отправляем подтверждение...")
                sys_reply = {"type": 2, "id": resp_id, "payload": {}} 
                await _active_websocket.send(json.dumps(sys_reply)) 
 
            elif resp_type == 2 and resp_id == 1: 
                logging.info("[Слушатель] Подтверждение авторизации от сервера получено успешно.")
 
    except websockets.exceptions.ConnectionClosed: 
        logging.warning("[Слушатель] Фоновое WebSocket соединение закрыто сервером.")
        _active_websocket = None 

async def send_trueconf_message(token, text): 
    """ 
    Асинхронная отправка пакета sendMessage в открытый фоновый поток.
    """ 
    global _active_websocket, _request_id 
 
    if not _active_websocket: 
        logging.warning("Фоновое соединение отсутствует. Переподключение сокета...")
        return 401 
 
    chat_id = os.getenv("TRUECONF_CHAT_ID") 
 
    # Полностью очищаем ID чата от префиксов согласно официальной инструкции TrueConf
    clean_guid = str(chat_id).replace('#', '').replace('c_', '').split('@')[0].strip() 
 
    _request_id += 1 
 
    # Структура приведена в 100% соответствие с официальной документацией TrueConf 
    message_payload = { 
        "type": 1, 
        "id": _request_id, 
        "method": "sendMessage", 
        "payload": { 
            "chatId": clean_guid, 
            "content": { 
                "text": text, 
                "parseMode": "markdown" 
            } 
        } 
    } 
 
    try: 
        logging.info(f"Асинхронная отправка инцидента на chatId: {clean_guid} (ID пакета: {_request_id})...")
        await _active_websocket.send(json.dumps(message_payload)) 
 
        # Даем Event Loop время протолкнуть байты в сеть до засыпания главного цикла
        await asyncio.sleep(0.2) 
        return True 
    except Exception as err: 
        logging.error(f"Ошибка при записи пакета в WebSocket: {err}") 
        return False
