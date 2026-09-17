import os
import time
import logging
import asyncio
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Импорт конфигурации и модулей MaxPatrol VM
from api_mp_vm.mp_vm_variables import mpvm_base_url
from api_mp_vm.vm_authentication import vm_authentificate
from api_mp_vm.mp_vm_incidents import get_fresh_incidents, format_incident_data

# Импорт асинхронных модулей TrueConf Server
from api_trueconf.tc_authentication import get_trueconf_token
from api_trueconf.tc_messages import init_trueconf_connection, send_trueconf_message

# Глобальная инициализация переменных окружения
load_dotenv()

log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level_str, logging.INFO),
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

PAUSE_TIME = int(os.getenv("PAUSE_TIME", 60))

def load_last_incident_time():
    try:
        with open("last_incident_time.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        # Отнимаем 2 часа — это гарантирует стабильный ответ 200 OK от API SIEM
        now_time = datetime.utcnow() - timedelta(hours=2) 
        one_day_ago = now_time.strftime("%Y-%m-%dT%H:%M:%SZ") 
        logging.info(f"Файл временной метки не найден. Инициализация поиска с UTC метки SIEM: {one_day_ago}")
        return one_day_ago

def save_last_incident_time(time_str):
    """Сохраняет временную метку последнего обработанного инцидента."""
    with open("last_incident_time.txt", "w") as f:
        f.write(time_str)

async def main_async_loop():
    """
    Главный асинхронный координирующий цикл мониторинга.
    """
    logging.info("Инициализация главного асинхронного цикла интеграции SIEM -> TrueConf...")
    
    # 1. Авторизация в MaxPatrol VM
    mp_token = vm_authentificate(mpvm_base_url)
    if not mp_token:
        logging.critical("Не удалось выполнить первоначальный вход в MaxPatrol VM. Скрипт остановлен.")
        return

    # 2. HTTP-авторизация в TrueConf Server для генерации JWT-токена
    tc_token = get_trueconf_token()
    if not tc_token:
        logging.critical("Не удалось выполнить первоначальный вход в TrueConf Server. Скрипт остановлен.")
        return

    # 3. Инициализация фонового сокета
    if not await init_trueconf_connection(tc_token):
        logging.critical("Не удалось запустить фоновый WebSocket клиент TrueConf. Скрипт остановлен.")
        return

    logging.info("Асинхронный движок запущен. Начат мониторинг.")
    await send_trueconf_message(tc_token, "🔄 Бот интеграции MaxPatrol VM ➔ TrueConf успешно запущен в асинхронном Event Loop.")

    while True: 
        try: 
            last_time = load_last_incident_time() 
            incidents = get_fresh_incidents(mp_token, last_time) 
 
            if incidents == 401: 
                logging.info("[Событие] Токен MaxPatrol VM истек. Переавторизация...")
                mp_token = vm_authentificate(mpvm_base_url) 
                if mp_token: 
                    continue 
                else: 
                    logging.error("Ошибка обновления сессии MaxPatrol VM. Ожидание...")
                    await asyncio.sleep(30) 
                    continue 
 
            if incidents and len(incidents) > 0: 
                logging.info(f"Обнаружено новых инцидентов в SIEM: {len(incidents)}") 
 
                for inc in reversed(incidents): 
                    clean_text = format_incident_data(mp_token, inc) 
 
                    # Пробуем отправить инцидент
                    tc_response = await send_trueconf_message(tc_token, clean_text) 
 
                    # Сценарий 1: Токен TrueConf протух или сокет упал
                    if tc_response == 401: 
                        logging.info("[Событие] Соединение сокета TrueConf отсутствует. Пробуем переподключиться...") 
                        tc_token = get_trueconf_token() 
                        if tc_token and await init_trueconf_connection(tc_token): 
                            # Пробуем отправить повторно после успешного переподключения
                            tc_response = await send_trueconf_message(tc_token, clean_text) 
                        else: 
                            tc_response = False  # Переподключиться не удалось
 
                    # Сценарий 2: Сервер TrueConf всё еще недоступен (или повторная отправка провалилась)
                    if not tc_response or tc_response == 401:
                        logging.error("❌ TrueConf недоступен. Прерываем отправку текущей пачки инцидентов до восстановления связи.")
                        # ВАЖНО: Мы делаем break, а не continue. 
                        # Цикл по текущим инцидентам останавливается. Временная метка НЕ обновляется.
                        break 
 
                    # Сценарий 3: Успешная отправка инцидента. Только теперь фиксируем его время!
                    if inc.get('created'): 
                        base_time_str = inc['created'].replace('Z', '')[:23] 
                        created_dt = datetime.fromisoformat(base_time_str) + timedelta(milliseconds=1) 
                        created_ms = created_dt.replace(microsecond=int(created_dt.microsecond / 1000) * 1000) 
                        new_last_time = created_ms.isoformat() + 'Z' 
                        save_last_incident_time(new_last_time) 
 
                    await asyncio.sleep(0.5) 
            else: 
                logging.debug("Новых инцидентов в MaxPatrol VM не зафиксировано.")
        except Exception as err: 
            logging.error(f"[Ошибка] Критическое исключение внутри рабочего цикла: {err}")
 
        # Асинхронная пауза, не блокирующая фоновые сетевые потоки сокета
        await asyncio.sleep(PAUSE_TIME)

if __name__ == "__main__":
    # Запуск единой асинхронной среды выполнения
    asyncio.run(main_async_loop())
