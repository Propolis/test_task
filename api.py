import time
from datetime import datetime
from zeep import Client
import pyodbc
import urllib3
from requests import Session
from zeep.transports import Transport
import ssl
from zeep.wsse.username import UsernameToken

urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context


session = Session()
session.verify = False
transport = Transport(session=session)

my_ip = input('Введите имя сервера (DNS имя или IP ПК на котором установлен сервер RusGuard): ')
my_login = input('Введите имя пользователя: ')
my_password = input('Введите пароль: ')

try:
    client = Client(f'https://{my_ip}/LNetworkServer/LNetworkService.svc?wsdl', wsse=UsernameToken(my_login, my_password), transport=transport)
except:
    print('Ошибка: Неверно указан сервер')
else:
    try:
        print('Соединение успешно установленно\nВерсия БД: ',client.service.GetVariable('Version').Value)
    except:
        print('Ошибка: Неверное имя пользователя или пароль')


def get_access_points():
    return client.service.GetAcsAccessPointDrivers()


def get_events(begin_date, end_date, event_filter):

    response = client.service.GetEventsByDeviceIDs(
        0,
        begin_date,
        end_date,
        None,
        event_filter,
        None,
        "None",
        0,
        100,
        "DateTime",
        "Ascending"
    )
    return response


def save_events_to_db(messages, cursor, conn):
    insert_query = """
        INSERT INTO EventsLog (EventID, EventDateTime, DriverID, DriverName, LogMsgSubType)
        VALUES (?, ?, ?, ?, ?)
    """
    for m in messages:
        try:
            cursor.execute(insert_query, m.Id, m.DateTime, m.DriverID, m.DriverName, str(m.LogMsgSubType))
        except Exception as e:
            return f"Ошибка при сохранении события {m.Id}: {e}"
    conn.commit()


def continuously_get_events(conn, cursor, event_filter, poll_interval=10):

    LogSubjectType = client.get_type("ns0:LogSubjectType")

    last_data = client.service.GetLastEvent(
        None,
        event_filter,
        None,
        LogSubjectType("None")
    )

    if last_data and last_data.Messages and hasattr(last_data, "Messages"):
        current_begin_date = max(msg.DateTime for msg in last_data.Messages)
    else:
        current_begin_date = datetime.now()

    while True:
        # На каждом шаге будем брать события от current_begin_date до текущего момента
        now = datetime.now()

        # Получаем события
        events = get_events(current_begin_date, now, event_filter)

        # Обрабатываем полученные события
        if events and hasattr(events, "Messages") and events.Messages:
            messages = events.Messages
            all_dates = [event.DateTime for event in messages]
            save_events_to_db(messages, cursor, conn)

            # Обновляем "начало" на самую свежую метку времени
            last_datetime = max(all_dates)
            # Если last_datetime больше текущего current_begin_date, сдвигаем
            if last_datetime > current_begin_date:
                current_begin_date = last_datetime

        time.sleep(poll_interval)


def main():
    LogMsgSubType = client.get_type("ns0:LogMsgSubType")
    event_filter = [
        LogMsgSubType("AccessPointEntryByKey"),
        LogMsgSubType("AccessPointFirstPersonEntry"),
        LogMsgSubType("AccessPointSecondPersonEntry"),
        LogMsgSubType("AccessPointExitByKey"),
        LogMsgSubType("AccessPointExitByCardReceiver"),
        LogMsgSubType("AccessPointFirstPersonExit"),
        LogMsgSubType("AccessPointFirstPersonExitByCardReceiver"),
        LogMsgSubType("AccessPointSecondPersonExit"),
        LogMsgSubType("AccessPointSecondPersonExitByCardReceiver")
    ]

    access_points = get_access_points()
    print(access_points)

    conn_str = (
        "DRIVER={ODBC Driver 17 for SQL Server};"
        "SERVER=sql_server;"
        "DATABASE=database;"
        "UID=username;"
        "PWD=password"
    )
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        print("Соединение с базой данных установлено.")
    except Exception as e:
        print("Ошибка подключения к БД:", e)
        exit()
    try:
        continuously_get_events(conn=conn, cursor=cursor, event_filter=event_filter, poll_interval=10)
    except KeyboardInterrupt:
        print("Выходим из кода")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
