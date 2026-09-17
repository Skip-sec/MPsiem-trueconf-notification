import logging 
import requests 
from datetime import datetime 
from api_mp_vm.mp_vm_variables import mpvm_base_url, MPVM_HTTPS_VERIFY, MAX_EVENTS_COUNT

def get_fresh_incidents(token, time_from): 
    """ 
    Запрос списка новых инцидентов из MaxPatrol VM / SIEM.
    """ 
    logging.info("Запуск модуля get_fresh_incidents()")
    url = f"{mpvm_base_url}/api/v2/incidents/" 
    
    # Payload полностью скопирован из гарантированно рабочего репозитория
    payload = {
        "offset": 0,
        "limit": 50,
        "groups": {"filterType": "no_filter"},
        "timeFrom": time_from,
        "timeTo": None,
        "filterTimeType": "creation",
        "filter": {
            "select": ["key", "name", "category", "type", "status", "created", "assigned"],
            "orderby": [
                {
                    "field": "created",
                    "sortOrder": "descending"
                },
                {
                    "field": "status",
                    "sortOrder": "ascending"
                },
                {
                    "field": "severity",
                    "sortOrder": "descending"
                }
            ]
        },
        "queryIds": ["all_incidents"]
    }
    
    headers = {
        "Content-Type": "application/json", 
        "Authorization": f"Bearer {token}",
        "User-Agent": "PostmanRuntime/7.42.0"
    } 
    
    try: 
        response = requests.post(url, json=payload, headers=headers, verify=MPVM_HTTPS_VERIFY, timeout=30) 
        
        if response.status_code == 500:
            logging.error(f"❌ Детальный ответ сервера 500: {response.text}")
        
        if response.status_code == 401: 
            logging.warning("Получен код 401 от MaxPatrol VM. Токен авторизации устарел.")
            return 401 
        
        response.raise_for_status() 
        incidents = response.json().get('incidents', []) 
        logging.info(f"Успешно получено инцидентов из MaxPatrol: {len(incidents)}") 
        return incidents 
    
    except Exception as err: 
        logging.error(f"Ошибка при выполнении запроса инцидентов из MaxPatrol: {err}") 
        return [] 

def get_events_by_incident_id(token, incident_id):
    """
    Запрос связанных событий ИБ по ID инцидента из MaxPatrol SIEM.
    """
    url = f"{mpvm_base_url}/api/incidents/{incident_id}/events"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "PostmanRuntime/7.42.0"
    }
    
    try:
        response = requests.get(url, headers=headers, verify=MPVM_HTTPS_VERIFY, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"❌ Ошибка получения событий для {incident_id}: Код {response.status_code}")
            return []
    except Exception as err:
        logging.error(f"❌ Исключение при запросе событий для инцидента {incident_id}: {err}")
        return []


def format_incident_data(token, incident):
    """
    Парсинг JSON структуры инцидента и добавление связанных событий ИБ.
    """
    try:
        created_raw = incident.get('created', '')
        inc_date = datetime.fromisoformat(created_raw[:23]).strftime("%Y.%m.%d %H:%M:%S") if created_raw else "Н/Д"
        
        inc_id = incident.get('id', '')
        inc_key = incident.get('key', 'N/A') 
        inc_type = incident.get('type', 'N/A') 
        inc_name = incident.get('name', 'Без описания')
        inc_status = incident.get('status', 'New') 
        inc_severity = incident.get('severity', 'Low') 
        inc_link = f"{mpvm_base_url}/#/incident/incidents/view/{inc_id}" 
        
        severity_map = { 
            "High": "ВЫСОКАЯ 🔴", 
            "Medium": "СРЕДНЯЯ 🟠", 
            "Low": "НИЗКАЯ 🟡" 
        } 
        severity_str = severity_map.get(inc_severity, inc_severity) 
        
        # --- БЛОК СБОРА СОБЫТИЙ --- 
        events = get_events_by_incident_id(token, inc_id) 
        events_str = " --- Инцидент без связанных событий --- "
 
        if events and len(events) > 0: 
            # Убрали тройные кавычки, оставляем чистую строку
            events_str = "" 
            ev_number = 0 
            for ev in events: 
                ev_number += 1 
                # Парсинг даты события
                ev_date_raw = ev.get('date', '') 
                ev_date = datetime.fromisoformat(ev_date_raw[:23]).strftime("%Y.%m.%d %H:%M:%S") if ev_date_raw else "Н/Д"
                ev_description = ev.get('description', 'Без описания')
 
                # Собираем строки событий
                events_str += f"[{ev_number}] Дата: {ev_date} | {ev_description}\n" 
 
                # Проверка лимита
                if ev_number == MAX_EVENTS_COUNT: 
                    if len(events) - ev_number > 0: 
                        # Выделяем количество оставшихся событий жирным шрифтом
                        events_str += f"**... и еще {len(events) - ev_number} событий.**\n" 
                    break 
        # --------------------------- 
        
        # Собираем единое сообщение. Выделяем заголовок событий жирным шрифтом
        msg = ( 
            f"🚨 [SIEM MaxPatrol] Обнаружен инцидент {inc_key}\n" 
            f"• Время: {inc_date}\n" 
            f"• Важность: {severity_str}\n" 
            f"• Тип: {inc_type}\n" 
            f"• Статус: {inc_status}\n" 
            f"• Описание: {inc_name}\n" 
            f"• Ссылка: [Открыть в MaxPatrol SIEM]({inc_link})\n"
            f"**— Тригерные события —**\n" 
            f"{events_str}" 
        ) 
        return msg 
        
    except Exception as ex_parse: 
        logging.error(f"Ошибка при парсинге полей инцидента: {ex_parse}")
        return "⚠️ Не удалось разобрать структуру инцидента MaxPatrol VM.", ""
