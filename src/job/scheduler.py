import time
import atexit

from apscheduler.schedulers.background import BackgroundScheduler

from src.repository import get_current_resources, load_resources_setting, \
    get_current_user_role_mappings, load_user_role_mappings, load_public_keys


def get_resource_data():
    print("reload resource data")
    resources = get_current_resources()
    list_resource_id = set()
    for resource in resources:
        list_resource_id.add(resource[0])
    load_resources_setting(list_resource_id)
    user_role_data = get_current_user_role_mappings()
    load_user_role_mappings(user_role_data)
    load_public_keys()
    print("reload data successfully")


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=get_resource_data, trigger="interval", seconds=10)
    scheduler.start()
