import logging
import os
import requests
import urllib3

# Отключение предупреждений SSL (для самоподписанных сертификатов внутри корпоративного контура)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_trueconf_token():
    """
    Выполняет POST-запрос к TrueConf Server API для получения OAuth токена.
    Использует учетные данные из файла .env.
    
    :return: Строка с токеном (str) в случае успеха, или None при ошибке.
    """
    logging.info("Старт модуля tc_authentication.get_trueconf_token()")
    
    # Считываем базовый URL сервера и параметры авторизации
    # Добавляем /bridge/api/v1/oauth/token к базовому URL, как на вашем скриншоте
    base_url = os.getenv("TRUECONF_SERVER_URL", "").rstrip("/")
    #url = f"{base_url}/bridge/api/v1/oauth/token"
    url = f"{base_url}/bridge/api/client/v1/oauth/token"
    
    headers = {
        "Content-Type": "application/json"
    }
    
    # Формируем JSON-тело запроса в строгом соответствии с вашим скриншотом из Postman
    data = {
        "client_id": "chat_bot",
        "grant_type": "password",
        "username": os.getenv("TRUECONF_USER"),
        "password": os.getenv("TRUECONF_PASSWORD")
    }
    
    logging.info("Сборка параметров для авторизации TrueConf завершена")
    logging.debug(f"Попытка авторизации пользователя TrueConf: {data.get('username')}")
    logging.debug(f"URL подключения к TrueConf: {url}")
    
    try:
        # Отправляем POST запрос с таймаутом и отключенной проверкой сертификата
        response = requests.post(url, json=data, headers=headers, verify=False, timeout=30)
        
        # Проверка на ошибки 4xx/5xx (например, если логин или пароль неверные)
        response.raise_for_status() 
        
        logging.info("Успешное соединение с сервером авторизации TrueConf")
        
        # Извлекаем токен из JSON-ответа
        token = response.json().get("access_token")
        if token:
            logging.info("Токен авторизации TrueConf успешно получен")
            return token
        else:
            logging.error("В ответе сервера TrueConf отсутствует поле access_token")
            return None
            
    except Exception as err:
        logging.error(f"ОШИБКА при попытке авторизации в TrueConf Server:\n{err}")
        return None
